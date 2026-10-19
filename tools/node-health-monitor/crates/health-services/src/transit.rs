//! Development-only, same-host age witness for O-cache delivery to M.
//! An absent or invalid witness never invalidates an otherwise valid archive.
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

const VERSION: &str = "x-nhm-witness-clock-v1";
const BOOT: &str = "x-nhm-witness-boot-id";
const TIME_NS: &str = "x-nhm-witness-time-ns";
const START: &str = "x-nhm-witness-start-ns";
const BODY_HASH: &str = "x-nhm-witness-body-sha256";
const AUTH: &str = "x-nhm-witness-current-auth";
pub const HEADERS: [&str; 6] = [VERSION, BOOT, TIME_NS, START, BODY_HASH, AUTH];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    boot_id: String,
    time_ns: String,
    nanos: u64,
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

fn valid_time_ns(value: &str) -> bool {
    value.len() <= 32
        && value
            .strip_prefix("time:[")
            .and_then(|v| v.strip_suffix(']'))
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}

fn singleton<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    let mut values = headers.get_all(key).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

impl Stamp {
    pub fn capture() -> Option<Self> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let boot_id = boot_id.trim_end_matches('\n');
        let time_ns = std::fs::read_link("/proc/self/ns/time").ok()?.to_str()?.to_owned();
        if !valid_boot_id(boot_id) || !valid_time_ns(&time_ns) {
            return None;
        }
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: ts is an initialized, writable timespec and CLOCK_BOOTTIME is read-only.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
            return None;
        }
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return None;
        }
        let nanos = u64::try_from(ts.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(ts.tv_nsec).ok()?)?;
        Some(Self { boot_id: boot_id.to_owned(), time_ns, nanos })
    }

    pub fn add_headers(
        &self,
        request: reqwest::RequestBuilder,
        body: &[u8],
        token: &str,
    ) -> reqwest::RequestBuilder {
        request
            .header(VERSION, "1")
            .header(BOOT, &self.boot_id)
            .header(TIME_NS, &self.time_ns)
            .header(START, self.nanos.to_string())
            .header(BODY_HASH, crate::hex(&Sha256::digest(body)))
            .header(AUTH, token)
    }

    pub fn from_headers(headers: &HeaderMap, body: &[u8], expected_token: &[u8]) -> Option<Self> {
        use subtle::ConstantTimeEq;
        if singleton(headers, VERSION)? != "1" {
            return None;
        }
        let boot_id = singleton(headers, BOOT)?;
        let time_ns = singleton(headers, TIME_NS)?;
        let nanos_text = singleton(headers, START)?;
        let body_hash = singleton(headers, BODY_HASH)?;
        let credential = singleton(headers, AUTH)?;
        if !valid_boot_id(boot_id)
            || !valid_time_ns(time_ns)
            || tos_health_core::wire::exact_u64(nanos_text).is_err()
            || body_hash != crate::hex(&Sha256::digest(body))
            || !bool::from(
                Sha256::digest(credential.as_bytes()).ct_eq(&Sha256::digest(expected_token)),
            )
        {
            return None;
        }
        Some(Self {
            boot_id: boot_id.to_owned(),
            time_ns: time_ns.to_owned(),
            nanos: nanos_text.parse().ok()?,
        })
    }

    pub fn elapsed_ms_at(&self, end: &Self) -> Option<u64> {
        if self.boot_id != end.boot_id || self.time_ns != end.time_ns {
            return None;
        }
        let nanos = end.nanos.checked_sub(self.nanos)?;
        nanos.checked_add(999_999).map(|v| v / 1_000_000)
    }

    pub fn elapsed_ms_now(&self) -> Option<u64> {
        self.elapsed_ms_at(&Self::capture()?)
    }

    pub fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.boot_id.capacity())
            .saturating_add(self.time_ns.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(stamp: &Stamp, body: &[u8], token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(VERSION, HeaderValue::from_static("1"));
        headers.insert(BOOT, HeaderValue::from_str(&stamp.boot_id).unwrap());
        headers.insert(TIME_NS, HeaderValue::from_str(&stamp.time_ns).unwrap());
        headers.insert(START, HeaderValue::from_str(&stamp.nanos.to_string()).unwrap());
        headers
            .insert(BODY_HASH, HeaderValue::from_str(&crate::hex(&Sha256::digest(body))).unwrap());
        headers.insert(AUTH, HeaderValue::from_str(token).unwrap());
        headers
    }

    #[test]
    fn same_host_stamp_is_bound_to_singleton_headers_body_and_monotonic_order() {
        let stamp = Stamp::capture().expect("Linux same-host clock available");
        let body = br#"{"source":"synthetic"}"#;
        let token = "a".repeat(32);
        let mut wire = headers(&stamp, body, &token);
        assert_eq!(Stamp::from_headers(&wire, body, token.as_bytes()), Some(stamp.clone()));
        assert!(stamp.elapsed_ms_now().is_some());
        assert!(Stamp::from_headers(&wire, b"changed", token.as_bytes()).is_none());
        assert!(
            Stamp::from_headers(&wire, body, b"different-token-with-sufficient-length").is_none()
        );
        wire.append(START, HeaderValue::from_static("1"));
        assert!(Stamp::from_headers(&wire, body, token.as_bytes()).is_none());
        let later = Stamp { nanos: stamp.nanos.saturating_sub(1), ..stamp.clone() };
        assert!(stamp.elapsed_ms_at(&later).is_none());
        let other_namespace = Stamp { time_ns: "time:[999999]".into(), ..stamp.clone() };
        assert!(stamp.elapsed_ms_at(&other_namespace).is_none());
        let other_boot =
            Stamp { boot_id: "00000000-0000-0000-0000-000000000000".into(), ..stamp.clone() };
        assert!(stamp.elapsed_ms_at(&other_boot).is_none());
    }
}
