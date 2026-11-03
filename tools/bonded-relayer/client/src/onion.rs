// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! A canonical v3 onion HTTP origin: `http://<56 base32>.onion[:port]`,
//! version and checksum verified, nothing else accepted.
use anyhow::{bail, ensure, Result};
use sha3::{Digest, Sha3_256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnionEndpoint {
    host: String,
    port: u16,
}

/// 56 lowercase base32 characters (RFC 4648 alphabet, `a-z2-7`) to 35 bytes.
fn base32_decode_56(text: &str) -> Result<[u8; 35]> {
    ensure!(text.len() == 56, "onion host length");
    let mut out = [0u8; 35];
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    let mut written = 0usize;
    for c in text.bytes() {
        let value = match c {
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => bail!("onion host alphabet"),
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((buffer >> bits) & 0xff)?;
            ensure!(written < out.len(), "onion host overflow");
            out[written] = byte;
            written += 1;
        }
    }
    ensure!(written == 35 && (buffer & ((1u64 << bits) - 1)) == 0, "onion host padding");
    Ok(out)
}

impl OnionEndpoint {
    /// `http://` + host + optional `:port` (1..65535, written without leading
    /// zeros; `:80` is the default and must be omitted). The host's decoded
    /// bytes carry version 3 and the checksum of its public key.
    pub fn parse(origin: &str) -> Result<Self> {
        let rest = origin
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("canonical HTTP v3 onion origin required"))?;
        let (host, port) = match rest.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (rest, None),
        };
        let label = host
            .strip_suffix(".onion")
            .ok_or_else(|| anyhow::anyhow!("canonical HTTP v3 onion origin required"))?;
        let decoded = base32_decode_56(label)
            .map_err(|_| anyhow::anyhow!("canonical HTTP v3 onion origin required"))?;
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(&decoded[..32]);
        hasher.update([3u8]);
        let checksum = hasher.finalize();
        ensure!(
            decoded[34] == 3 && decoded[32..34] == checksum[..2],
            "invalid v3 onion checksum or version"
        );
        let number = match port {
            None => 80,
            Some(text) => {
                ensure!(
                    !text.is_empty()
                        && text.len() <= 5
                        && text.bytes().all(|b| b.is_ascii_digit())
                        && !text.starts_with('0'),
                    "canonical HTTP v3 onion origin required"
                );
                let number: u32 = text.parse()?;
                ensure!((1..=65535).contains(&number), "integer out of range");
                ensure!(number != 80, "omit the default onion port");
                u16::try_from(number)?
            }
        };
        Ok(Self { host: host.to_owned(), port: number })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The HTTP `Host` value.
    pub fn authority(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn origin(&self) -> String {
        format!("http://{}", self.authority())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    pub(crate) const ORIGIN: &str =
        "http://pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

    #[test]
    fn canonical_v3_origin_and_checksum() -> Result<()> {
        let endpoint = OnionEndpoint::parse(ORIGIN)?;
        assert_eq!(endpoint.authority(), ONION);
        assert_eq!(endpoint.origin(), ORIGIN);
        assert_eq!(OnionEndpoint::parse(&format!("{ORIGIN}:8080"))?.port(), 8080);
        assert_eq!(
            OnionEndpoint::parse(&format!("{ORIGIN}:8080"))?.authority(),
            format!("{ONION}:8080")
        );
        let mut altered = ONION[..ONION.len() - 7].to_owned();
        altered.push_str("a.onion");
        for bad in [
            format!("{ORIGIN}/"),
            format!("{ORIGIN}:80"),
            format!("{ORIGIN}:080"),
            format!("{ORIGIN}:65536"),
            format!("{ORIGIN}:0"),
            format!("{ORIGIN}?"),
            format!("{ORIGIN}#"),
            ORIGIN.replace("http:", "https:"),
            ORIGIN.to_uppercase(),
            format!("http://user@{ONION}"),
            "http://example.com".to_owned(),
            "http://127.0.0.1".to_owned(),
            format!("http://{}.onion", "a".repeat(56)),
            format!("http://{altered}"),
            format!("{ORIGIN}\n"),
            format!("\t{ORIGIN}"),
            format!("{ORIGIN}."),
            format!("http://www.{ONION}"),
            String::new(),
        ] {
            assert!(OnionEndpoint::parse(&bad).is_err(), "accepted {bad:?}");
        }
        Ok(())
    }

    #[test]
    fn checksum_and_version_are_named() {
        // Same key, a flipped checksum byte: the host decodes but is not an onion.
        let mut raw = base32_decode_56(&ONION[..56]).ok().unwrap_or([0; 35]);
        raw[32] ^= 1;
        let mut text = String::new();
        let mut buffer: u64 = 0;
        let mut bits = 0u32;
        for byte in raw {
            buffer = (buffer << 8) | u64::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let v = ((buffer >> bits) & 31) as u8;
                text.push(if v < 26 { (b'a' + v) as char } else { (b'2' + v - 26) as char });
            }
        }
        let error =
            OnionEndpoint::parse(&format!("http://{text}.onion")).err().map(|e| e.to_string());
        assert_eq!(error.as_deref(), Some("invalid v3 onion checksum or version"));
    }
}
