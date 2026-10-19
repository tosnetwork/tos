use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardState {
    Normal,
    Guarded,
    Emergency,
    Recovering,
}
#[derive(Debug, Clone, Copy)]
pub struct Signals {
    pub sampled_ms: u64,
    pub valid: bool,
    pub pressure: bool,
    pub business_degraded: bool,
    pub oom_or_reserve_exhausted: bool,
}
#[derive(Debug)]
pub struct Guard {
    pub state: GuardState,
    pressure_since: Option<u64>,
    recovery_since: Option<u64>,
    last_tick: u64,
    has_tick: bool,
}
impl Default for Guard {
    fn default() -> Self {
        Self {
            state: GuardState::Guarded,
            pressure_since: None,
            recovery_since: None,
            last_tick: 0,
            has_tick: false,
        }
    }
}
impl Guard {
    pub fn update(&mut self, now: u64, signals: Signals) -> GuardState {
        let valid = now >= self.last_tick
            && signals.valid
            && signals.sampled_ms <= now
            && now.saturating_sub(signals.sampled_ms) <= 15_000;
        if self.has_tick && now.saturating_sub(self.last_tick) > 15_000 {
            self.recovery_since = None;
            self.pressure_since = None;
            if self.state != GuardState::Emergency {
                self.state = GuardState::Guarded;
            }
        }
        self.has_tick = true;
        self.last_tick = self.last_tick.max(now);
        if signals.oom_or_reserve_exhausted {
            self.state = GuardState::Emergency;
            self.recovery_since = None;
        } else if !valid || signals.business_degraded {
            if self.state != GuardState::Emergency {
                self.state = GuardState::Guarded;
            }
            self.recovery_since = None;
        } else if signals.pressure {
            let since = *self.pressure_since.get_or_insert(now);
            if now.saturating_sub(since) >= 30_000 && self.state != GuardState::Emergency {
                self.state = GuardState::Guarded;
            }
            self.recovery_since = None;
        } else {
            self.pressure_since = None;
            if self.state != GuardState::Normal {
                self.state = GuardState::Recovering;
                let since = *self.recovery_since.get_or_insert(now);
                if now.saturating_sub(since) >= 300_000 {
                    self.state = GuardState::Normal;
                }
            }
        }
        self.state
    }
    pub fn allow_diagnostics(&self) -> bool {
        self.state == GuardState::Normal
    }
}
