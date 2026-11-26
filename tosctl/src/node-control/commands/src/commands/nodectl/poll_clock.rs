//! The polling time source. Production keeps Tokio's timer and deadline semantics.

use std::{future::Future, time::Duration};

#[derive(Debug)]
pub(crate) struct PollTimeout;

pub(crate) trait PollClock {
    async fn sleep(&self, duration: Duration);
    async fn timeout<F: Future>(
        &self,
        duration: Duration,
        future: F,
    ) -> Result<F::Output, PollTimeout>;
}

pub(crate) struct TokioClock;

impl PollClock for TokioClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    async fn timeout<F: Future>(
        &self,
        duration: Duration,
        future: F,
    ) -> Result<F::Output, PollTimeout> {
        tokio::time::timeout(duration, future).await.map_err(|_| PollTimeout)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        task::Poll,
    };

    #[derive(Default)]
    pub(crate) struct FakeClock {
        elapsed: Cell<Duration>,
        deadline: Cell<Option<Duration>>,
        sleeps: RefCell<Vec<Duration>>,
    }

    impl FakeClock {
        pub(crate) fn elapsed(&self) -> Duration {
            self.elapsed.get()
        }
        pub(crate) fn sleeps(&self) -> Vec<Duration> {
            self.sleeps.borrow().clone()
        }
    }

    impl PollClock for FakeClock {
        async fn sleep(&self, duration: Duration) {
            pause_gate();
            let mut started = false;
            std::future::poll_fn(|cx| {
                if started {
                    return Poll::Ready(());
                }
                started = true;
                self.sleeps.borrow_mut().push(duration);
                let next = self.elapsed.get().checked_add(duration).expect("fake clock overflow");
                self.elapsed.set(self.deadline.get().map_or(next, |deadline| next.min(deadline)));
                cx.waker().wake_by_ref();
                Poll::Pending
            })
            .await
        }

        async fn timeout<F: Future>(
            &self,
            duration: Duration,
            future: F,
        ) -> Result<F::Output, PollTimeout> {
            let deadline =
                self.elapsed.get().checked_add(duration).expect("fake deadline overflow");
            let previous = self.deadline.replace(Some(deadline));
            assert!(previous.is_none(), "nested fake deadlines are not supported");
            let _reset = scopeguard::guard(previous, |before| self.deadline.set(before));
            let mut future = std::pin::pin!(future);
            std::future::poll_fn(|cx| {
                // Like Tokio, poll the operation before checking its deadline.
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => Poll::Ready(Ok(value)),
                    Poll::Pending if self.elapsed.get() >= deadline => {
                        Poll::Ready(Err(PollTimeout))
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        }
    }

    // A blocking worker prevents Tokio's idle auto-advance from racing real
    // loopback I/O. Each tick advances a fixed duration, never the wall-clock
    // delta: suspension therefore cannot consume a transport deadline.
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
    pub(crate) fn pause_gate() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        if std::env::var_os("VOTE_CMD_PAUSE_GATE").is_none() {
            return;
        }
        ONCE.call_once(|| {
            use std::io::Read;
            let before = tokio::time::Instant::now();
            eprintln!("VOTE_CMD_PAUSE_READY");
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

    #[tokio::test(start_paused = true)]
    async fn fake_deadlines_match_tokio_without_elapsed_wall_time() {
        let interval = Duration::from_secs(3);
        let limit = Duration::from_secs(10);
        let fake = FakeClock::default();
        let simulated = fake
            .timeout(limit, async {
                loop {
                    fake.sleep(interval).await;
                }
            })
            .await;
        assert!(simulated.is_err());
        assert_eq!(fake.elapsed(), limit);
        assert_eq!(fake.sleeps(), vec![interval; 4]);
        let real = TokioClock;
        let started = tokio::time::Instant::now();
        let production = real
            .timeout(limit, async {
                loop {
                    real.sleep(interval).await;
                }
            })
            .await;
        assert!(production.is_err());
        assert_eq!(started.elapsed(), limit);
    }

    #[tokio::test(start_paused = true)]
    async fn an_immediately_ready_operation_wins_a_zero_deadline() {
        assert_eq!(FakeClock::default().timeout(Duration::ZERO, async { 7 }).await.unwrap(), 7);
        assert_eq!(TokioClock.timeout(Duration::ZERO, async { 7 }).await.unwrap(), 7);
    }
}
