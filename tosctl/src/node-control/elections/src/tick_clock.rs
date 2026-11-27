/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! The runner's tick source. Production keeps Tokio's interval semantics.

use std::time::Duration;

pub(crate) trait TickClock {
    type Ticks<'a>: Ticks
    where
        Self: 'a;
    /// Ticks every `period`; the first tick completes at once.
    fn ticks(&self, period: Duration) -> Self::Ticks<'_>;
}

pub(crate) trait Ticks {
    /// Completes at the next tick. Cancel-safe: a tick dropped before it
    /// completes is still the next one.
    async fn tick(&mut self);
}

pub(crate) struct TokioClock;

impl TickClock for TokioClock {
    type Ticks<'a> = tokio::time::Interval;

    fn ticks(&self, period: Duration) -> tokio::time::Interval {
        tokio::time::interval(period)
    }
}

impl Ticks for tokio::time::Interval {
    async fn tick(&mut self) {
        tokio::time::Interval::tick(self).await;
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::{cell::Cell, future::Future, task::Poll};

    #[derive(Debug)]
    pub(crate) struct FakeTimeout;

    impl std::fmt::Display for FakeTimeout {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fake deadline elapsed")
        }
    }

    impl std::error::Error for FakeTimeout {}

    /// Logical time: it moves only when a tick waits for it, never with the
    /// wall clock, so a suspended process cannot consume a deadline.
    #[derive(Default)]
    pub(crate) struct FakeClock {
        elapsed: Cell<Duration>,
        deadline: Cell<Option<Duration>>,
        ticks: Cell<usize>,
    }

    impl FakeClock {
        pub(crate) fn elapsed(&self) -> Duration {
            self.elapsed.get()
        }

        /// Ticks completed so far, by every ticker of this clock.
        pub(crate) fn ticks_completed(&self) -> usize {
            self.ticks.get()
        }

        /// Like `tokio::time::timeout`, on logical time: the operation gets one
        /// more poll at the deadline instant before the deadline wins.
        pub(crate) async fn timeout<F: Future>(
            &self,
            duration: Duration,
            future: F,
        ) -> Result<F::Output, FakeTimeout> {
            struct Restore<'a>(&'a Cell<Option<Duration>>, Option<Duration>);
            impl Drop for Restore<'_> {
                fn drop(&mut self) {
                    self.0.set(self.1);
                }
            }
            let deadline =
                self.elapsed.get().checked_add(duration).expect("fake deadline overflow");
            let previous = self.deadline.replace(Some(deadline));
            assert!(previous.is_none(), "nested fake deadlines are not supported");
            let _restore = Restore(&self.deadline, previous);
            let mut future = std::pin::pin!(future);
            std::future::poll_fn(|cx| {
                let elapsed_before_poll = self.elapsed.get();
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => Poll::Ready(Ok(value)),
                    Poll::Pending if elapsed_before_poll >= deadline => {
                        Poll::Ready(Err(FakeTimeout))
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        }
    }

    pub(crate) struct FakeTicks<'a> {
        clock: &'a FakeClock,
        period: Duration,
        next: Option<Duration>,
    }

    impl TickClock for FakeClock {
        type Ticks<'a> = FakeTicks<'a>;

        fn ticks(&self, period: Duration) -> FakeTicks<'_> {
            FakeTicks { clock: self, period, next: None }
        }
    }

    impl Ticks for FakeTicks<'_> {
        async fn tick(&mut self) {
            pause_gate();
            let clock = self.clock;
            let due = self.next.unwrap_or_else(|| clock.elapsed.get());
            std::future::poll_fn(|cx| {
                if clock.elapsed.get() >= due {
                    return Poll::Ready(());
                }
                // Move logical time to the tick, never past a fake deadline.
                clock.elapsed.set(clock.deadline.get().map_or(due, |deadline| due.min(deadline)));
                cx.waker().wake_by_ref();
                Poll::Pending
            })
            .await;
            self.next = Some(due.checked_add(self.period).expect("fake clock overflow"));
            clock.ticks.set(clock.ticks.get() + 1);
        }
    }

    // A blocking worker prevents Tokio's idle auto-advance from racing real
    // loopback I/O. Each tick advances a fixed duration, never the wall-clock
    // delta: suspension therefore cannot consume a transport deadline.
    // Requires Tokio >= 1.24.0: a running spawn_blocking task inhibits paused
    // time's auto-advance (Tokio change #5115). tosctl/src/Cargo.lock pins 1.50.0.
    pub(crate) struct FrozenNetworkTime {
        stop: Option<std::sync::mpsc::Sender<()>>,
    }

    impl Drop for FrozenNetworkTime {
        fn drop(&mut self) {
            self.stop.take();
        }
    }

    pub(crate) async fn freeze_network_time() -> FrozenNetworkTime {
        tokio::time::pause();
        let (stop, receiver) = std::sync::mpsc::channel();
        let (ready, started) = tokio::sync::oneshot::channel();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _ = ready.send(());
            while receiver.recv_timeout(Duration::from_millis(10))
                == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            {
                runtime.block_on(tokio::time::advance(Duration::from_millis(10)));
            }
        });
        started.await.expect("transport clock worker started");
        FrozenNetworkTime { stop: Some(stop) }
    }

    // Opt-in rendezvous for the external SIGSTOP control, never a test deadline.
    // ELECTIONS_RUNNER_PAUSE_GATE is only for the control script's single-test
    // runs; setting it otherwise blocks on stdin until a controller supplies a
    // byte.
    pub(crate) fn pause_gate() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        if std::env::var_os("ELECTIONS_RUNNER_PAUSE_GATE").is_none() {
            return;
        }
        ONCE.call_once(|| {
            use std::io::Read;
            let before = tokio::time::Instant::now();
            eprintln!("ELECTIONS_RUNNER_PAUSE_READY");
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).expect("pause controller released the test");
            assert!(
                before.elapsed() < Duration::from_secs(1),
                "suspension consumed transport time"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::FakeClock, *};

    async fn count_ticks<C: TickClock>(
        clock: &C,
        period: Duration,
        ticks: &std::cell::Cell<usize>,
    ) {
        let mut ticker = clock.ticks(period);
        loop {
            ticker.tick().await;
            ticks.set(ticks.get() + 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fake_ticks_match_a_tokio_interval_without_elapsed_wall_time() {
        let period = Duration::from_secs(3);
        let limit = Duration::from_secs(10);
        let fake = FakeClock::default();
        let fake_ticks = std::cell::Cell::new(0);
        assert!(fake.timeout(limit, count_ticks(&fake, period, &fake_ticks)).await.is_err());
        let real_ticks = std::cell::Cell::new(0);
        let started = tokio::time::Instant::now();
        let real = tokio::time::timeout(limit, count_ticks(&TokioClock, period, &real_ticks)).await;
        assert!(real.is_err());
        // Ticks at 0, 3, 6 and 9 s, then the deadline at 10 s.
        assert_eq!(real_ticks.get(), 4);
        assert_eq!(fake_ticks.get(), real_ticks.get());
        assert_eq!(fake.ticks_completed(), 4);
        assert_eq!(fake.elapsed(), limit);
        assert_eq!(started.elapsed(), limit);
    }

    #[tokio::test(start_paused = true)]
    async fn an_exact_deadline_lets_the_tick_due_at_it_complete() {
        let period = Duration::from_secs(3);
        let limit = Duration::from_secs(9);
        let fake = FakeClock::default();
        let fake_ticks = std::cell::Cell::new(0);
        assert!(fake.timeout(limit, count_ticks(&fake, period, &fake_ticks)).await.is_err());
        let real_ticks = std::cell::Cell::new(0);
        let real = tokio::time::timeout(limit, count_ticks(&TokioClock, period, &real_ticks)).await;
        assert!(real.is_err());
        assert_eq!(real_ticks.get(), 4, "Tokio completes the tick due at the deadline");
        assert_eq!(fake_ticks.get(), real_ticks.get());
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_tick_is_still_the_next_one() {
        use std::future::Future;
        // Polls the second tick once and drops it before it is due, as a
        // select! does when its other branch wins. True if that poll completed it.
        async fn drop_then_tick<C: TickClock>(clock: &C) -> bool {
            let mut ticker = clock.ticks(Duration::from_secs(60));
            ticker.tick().await;
            let completed = {
                let mut abandoned = std::pin::pin!(ticker.tick());
                std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(abandoned.as_mut().poll(cx).is_ready())
                })
                .await
            };
            ticker.tick().await;
            completed
        }
        let fake = FakeClock::default();
        assert!(!drop_then_tick(&fake).await);
        assert_eq!(fake.elapsed(), Duration::from_secs(60));
        assert_eq!(fake.ticks_completed(), 2);
        let started = tokio::time::Instant::now();
        assert!(!drop_then_tick(&TokioClock).await);
        assert_eq!(started.elapsed(), Duration::from_secs(60));
    }
}
