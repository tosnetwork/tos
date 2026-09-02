/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use std::{collections::HashMap, net::IpAddr};

const LOGIN_ATTEMPT_WINDOW_SECS: u64 = 60;
const LOGIN_ATTEMPT_MAX_FAILURES: u32 = 5;
const LOGIN_ATTEMPT_BLOCK_SECS: u64 = 120;
const LOGIN_ATTEMPT_STALE_SECS: u64 = 900;
/// Per-username failure budget across all client addresses. This bounds a
/// brute-force attempt against a single account even when the attacker can
/// spread requests over many source addresses.
const USERNAME_ATTEMPT_WINDOW_SECS: u64 = 900;
const USERNAME_ATTEMPT_MAX_FAILURES: u32 = 20;
const MAX_LIMITER_ENTRIES: usize = 10_000;
const MAX_USERNAME_LEN: usize = 64;

#[derive(Default, Clone)]
/// In-memory limiter for `/auth/login` failure throttling.
///
/// Tracks two independent dimensions:
/// - per client-address-and-username buckets (`"<ip>:<username>"`), and
/// - per-username buckets across all client addresses.
///
/// A login is rejected while either dimension is blocked.
pub(crate) struct LoginRateLimiter {
    attempts: HashMap<String, LoginAttemptBucket>,
    username_attempts: HashMap<String, LoginAttemptBucket>,
}

#[derive(Clone, Copy)]
/// Per-key counters and timestamps used to
/// rate limit login attempts.
struct LoginAttemptBucket {
    /// Number of failed login attempts within the current time window.
    failures: u32,
    /// Unix timestamp (seconds) when the current failure window started.
    window_started_at: u64,
    /// Unix timestamp (seconds) until which this key remains blocked.
    blocked_until: u64,
    /// Unix timestamp (seconds) of the last activity for this key.
    last_seen_at: u64,
}

impl LoginAttemptBucket {
    fn new(now: u64) -> Self {
        Self { failures: 0, window_started_at: now, blocked_until: 0, last_seen_at: now }
    }

    fn record_failure(&mut self, now: u64, window_secs: u64, max_failures: u32) {
        if now.saturating_sub(self.window_started_at) > window_secs {
            self.failures = 0;
            self.window_started_at = now;
        }
        self.failures = self.failures.saturating_add(1);
        self.last_seen_at = now;
        if self.failures >= max_failures {
            self.blocked_until = now.saturating_add(LOGIN_ATTEMPT_BLOCK_SECS);
        }
    }
}

impl LoginRateLimiter {
    pub(crate) fn is_blocked(&mut self, client: IpAddr, username: &str, now: u64) -> bool {
        self.cleanup(now);
        let blocked =
            |b: Option<&LoginAttemptBucket>| b.map(|b| b.blocked_until > now).unwrap_or(false);
        blocked(self.attempts.get(&client_key(client, username)))
            || blocked(self.username_attempts.get(truncate_username(username)))
    }

    /// Records a failed login attempt. Returns `Err` if the limiter is at capacity
    /// and cannot track new keys (the caller should treat this as a rate-limit rejection).
    pub(crate) fn record_failure(
        &mut self,
        client: IpAddr,
        username: &str,
        now: u64,
    ) -> Result<(), ()> {
        self.cleanup(now);

        let key = client_key(client, username);
        let user_key = truncate_username(username);
        if !self.attempts.contains_key(&key) && self.attempts.len() >= MAX_LIMITER_ENTRIES {
            return Err(());
        }
        if !self.username_attempts.contains_key(user_key)
            && self.username_attempts.len() >= MAX_LIMITER_ENTRIES
        {
            return Err(());
        }

        self.attempts.entry(key).or_insert_with(|| LoginAttemptBucket::new(now)).record_failure(
            now,
            LOGIN_ATTEMPT_WINDOW_SECS,
            LOGIN_ATTEMPT_MAX_FAILURES,
        );
        self.username_attempts
            .entry(user_key.to_owned())
            .or_insert_with(|| LoginAttemptBucket::new(now))
            .record_failure(now, USERNAME_ATTEMPT_WINDOW_SECS, USERNAME_ATTEMPT_MAX_FAILURES);
        Ok(())
    }

    pub(crate) fn record_success(&mut self, client: IpAddr, username: &str) {
        self.attempts.remove(&client_key(client, username));
        self.username_attempts.remove(truncate_username(username));
    }

    fn cleanup(&mut self, now: u64) {
        let retain = |b: &LoginAttemptBucket| {
            let is_blocked = b.blocked_until > now;
            is_blocked || now.saturating_sub(b.last_seen_at) <= LOGIN_ATTEMPT_STALE_SECS
        };
        self.attempts.retain(|_, b| retain(b));
        self.username_attempts.retain(|_, b| retain(b));
    }
}

fn client_key(client: IpAddr, username: &str) -> String {
    format!("{client}:{}", truncate_username(username))
}

/// Resolves the client address a login attempt is attributed to.
///
/// The TCP peer address is authoritative: a direct client can put arbitrary
/// text in `x-forwarded-for`, so honoring it unconditionally would let an
/// attacker pick a fresh rate-limit bucket per request. The header is used
/// only when the peer itself is a configured trusted reverse proxy, and then
/// only its last entry — the one appended by that proxy and therefore the
/// only one it vouches for. An absent or unparseable value falls back to the
/// peer address.
pub(crate) fn client_ip(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted_proxies: &[IpAddr],
) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .and_then(|v| v.parse().ok())
        .unwrap_or(peer)
}

fn truncate_username(username: &str) -> &str {
    &username[..username.len().min(MAX_USERNAME_LEN)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    const CLIENT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_after_threshold_and_unblocks_after_duration() {
        let mut limiter = LoginRateLimiter::default();
        let now = 1_000;

        for _ in 0..(LOGIN_ATTEMPT_MAX_FAILURES - 1) {
            limiter.record_failure(CLIENT, "alice", now).unwrap();
        }
        assert!(!limiter.is_blocked(CLIENT, "alice", now));
        limiter.record_failure(CLIENT, "alice", now).unwrap();

        assert!(limiter.is_blocked(CLIENT, "alice", now));
        assert!(limiter.is_blocked(CLIENT, "alice", now + LOGIN_ATTEMPT_BLOCK_SECS - 1));
        assert!(!limiter.is_blocked(CLIENT, "alice", now + LOGIN_ATTEMPT_BLOCK_SECS));
    }

    #[test]
    fn failure_counter_resets_after_window() {
        let mut limiter = LoginRateLimiter::default();
        let now = 10;

        for _ in 0..(LOGIN_ATTEMPT_MAX_FAILURES - 1) {
            limiter.record_failure(CLIENT, "bob", now).unwrap();
        }

        // New attempt outside the counting window should start fresh.
        limiter.record_failure(CLIENT, "bob", now + LOGIN_ATTEMPT_WINDOW_SECS + 1).unwrap();
        assert!(!limiter.is_blocked(CLIENT, "bob", now + LOGIN_ATTEMPT_WINDOW_SECS + 1));
    }

    #[test]
    fn success_clears_failures() {
        let mut limiter = LoginRateLimiter::default();
        let now = 100;

        for _ in 0..(LOGIN_ATTEMPT_MAX_FAILURES - 1) {
            limiter.record_failure(CLIENT, "carol", now).unwrap();
        }
        limiter.record_success(CLIENT, "carol");

        limiter.record_failure(CLIENT, "carol", now).unwrap();
        assert!(!limiter.is_blocked(CLIENT, "carol", now));
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let mut limiter = LoginRateLimiter::default();
        let now = 200;

        limiter.record_failure(CLIENT, "dave", now).unwrap();
        assert!(limiter.attempts.contains_key(&client_key(CLIENT, "dave")));
        assert!(limiter.username_attempts.contains_key("dave"));

        // Trigger cleanup with a newer operation.
        let later = now + LOGIN_ATTEMPT_STALE_SECS + 1;
        let _ = limiter.is_blocked(ip("10.1.1.1"), "other", later);
        assert!(!limiter.attempts.contains_key(&client_key(CLIENT, "dave")));
        assert!(!limiter.username_attempts.contains_key("dave"));
    }

    #[test]
    fn username_budget_blocks_across_addresses() {
        let mut limiter = LoginRateLimiter::default();
        let now = 1_000;

        // Stay under the per-address threshold while exhausting the
        // per-username budget from many addresses.
        let per_ip = (LOGIN_ATTEMPT_MAX_FAILURES - 1) as u64;
        let mut failures = 0u32;
        let mut octet = 1u8;
        while failures < USERNAME_ATTEMPT_MAX_FAILURES {
            let client = ip(&format!("198.51.100.{octet}"));
            for _ in 0..per_ip {
                if failures >= USERNAME_ATTEMPT_MAX_FAILURES {
                    break;
                }
                limiter.record_failure(client, "erin", now).unwrap();
                failures += 1;
            }
            octet += 1;
        }

        // A fresh address is blocked for this username, but not for others.
        assert!(limiter.is_blocked(ip("203.0.113.77"), "erin", now));
        assert!(!limiter.is_blocked(ip("203.0.113.77"), "frank", now));
        assert!(!limiter.is_blocked(ip("203.0.113.77"), "erin", now + LOGIN_ATTEMPT_BLOCK_SECS));
    }

    #[test]
    fn client_ip_ignores_forwarded_header_from_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1, 10.0.0.2"));
        assert_eq!(client_ip(ip("203.0.113.5"), &headers, &[]), ip("203.0.113.5"));
        assert_eq!(client_ip(ip("203.0.113.5"), &headers, &[ip("192.0.2.1")]), ip("203.0.113.5"));
    }

    #[test]
    fn client_ip_uses_last_forwarded_entry_from_trusted_proxy() {
        let proxy = ip("192.0.2.1");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1, 10.0.0.2"));
        assert_eq!(client_ip(proxy, &headers, &[proxy]), ip("10.0.0.2"));

        // Absent or unparseable header falls back to the peer address.
        let empty = HeaderMap::new();
        assert_eq!(client_ip(proxy, &empty, &[proxy]), proxy);
        let mut garbage = HeaderMap::new();
        garbage.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip(proxy, &garbage, &[proxy]), proxy);
    }

    #[test]
    fn truncate_username_short() {
        assert_eq!(truncate_username("alice"), "alice");
    }

    #[test]
    fn truncate_username_exact_limit() {
        let name = "a".repeat(MAX_USERNAME_LEN);
        assert_eq!(truncate_username(&name), name.as_str());
    }

    #[test]
    fn truncate_username_over_limit() {
        let long = "a".repeat(MAX_USERNAME_LEN + 20);
        let expected = "a".repeat(MAX_USERNAME_LEN);
        assert_eq!(truncate_username(&long), expected);
    }

    #[test]
    fn record_failure_rejects_when_at_capacity() {
        let mut limiter = LoginRateLimiter::default();
        let now = 1_000;

        for i in 0..MAX_LIMITER_ENTRIES {
            // Distinct usernames from one address: bounds both tables.
            limiter.record_failure(CLIENT, &format!("user{i}"), now).unwrap();
        }

        assert!(limiter.record_failure(CLIENT, "overflow", now).is_err());
        // Existing key still works
        assert!(limiter.record_failure(CLIENT, "user0", now).is_ok());
    }
}
