//! Strict framing and correlation. Parsed frames do not establish authority.
use crate::{
    api_types::validate_api_binary,
    codec::{decode, Error, Hash},
    crypto::digest,
    types::{ApiError, ResultRequest, SignRequest},
};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFrame {
    pub method: u8,
    pub request_id: Hash,
    pub payload: Vec<u8>,
    pub response: bool,
    pub error: bool,
}
struct Json<'a> {
    raw: &'a [u8],
    pos: usize,
}
impl<'a> Json<'a> {
    fn space(&mut self) {
        while self.pos < self.raw.len()
            && matches!(self.raw[self.pos], b' ' | b'\t' | b'\r' | b'\n')
        {
            self.pos += 1;
        }
    }
    fn take(&mut self, c: u8) -> bool {
        self.space();
        if self.raw.get(self.pos) == Some(&c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn string(&mut self) -> Result<String, Error> {
        if !self.take(b'"') {
            return Err(Error("json-syntax"));
        }
        let mut out = String::new();
        while let Some(&byte) = self.raw.get(self.pos) {
            self.pos += 1;
            let mut c = byte;
            if c == b'"' {
                return Ok(out);
            }
            if !(32..128).contains(&c) {
                return Err(Error("transport-string"));
            }
            if c == b'\\' {
                let esc = *self.raw.get(self.pos).ok_or(Error("json-syntax"))?;
                self.pos += 1;
                c = match esc {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => 10,
                    b'r' => 13,
                    b't' => 9,
                    b'u' => {
                        let end = self.pos.checked_add(4).ok_or(Error("json-syntax"))?;
                        let digits = self.raw.get(self.pos..end).ok_or(Error("json-syntax"))?;
                        let mut value = 0u16;
                        for &digit in digits {
                            let n = match digit {
                                b'0'..=b'9' => digit - b'0',
                                b'a'..=b'f' => digit - b'a' + 10,
                                b'A'..=b'F' => digit - b'A' + 10,
                                _ => return Err(Error("json-syntax")),
                            };
                            value = value * 16 + u16::from(n);
                        }
                        self.pos = end;
                        if value >= 128 {
                            return Err(Error("transport-string"));
                        }
                        value as u8
                    }
                    _ => return Err(Error("json-syntax")),
                };
            }
            out.push(char::from(c));
        }
        Err(Error("json-syntax"))
    }
    fn parse(&mut self) -> Result<BTreeMap<String, Option<String>>, Error> {
        let mut fields = BTreeMap::new();
        if !self.take(b'{') {
            return Err(Error("json-syntax"));
        }
        if !self.take(b'}') {
            loop {
                let key = self.string()?;
                if fields.contains_key(&key) {
                    return Err(Error("duplicate-json-key"));
                }
                if fields.len() >= 4 {
                    return Err(Error("transport-fields"));
                }
                if !self.take(b':') {
                    return Err(Error("json-syntax"));
                }
                self.space();
                let value = if self.raw.get(self.pos..self.pos + 4) == Some(b"null") {
                    self.pos += 4;
                    None
                } else {
                    Some(self.string()?)
                };
                fields.insert(key, value);
                if self.take(b'}') {
                    break;
                }
                if !self.take(b',') {
                    return Err(Error("json-syntax"));
                }
            }
        }
        self.space();
        if self.pos != self.raw.len() {
            return Err(Error("json-syntax"));
        }
        Ok(fields)
    }
}
fn unhex(value: Option<&str>, limit: usize) -> Result<Vec<u8>, Error> {
    let value = value.ok_or(Error("hex"))?;
    if value.len() % 2 != 0 || value.len() / 2 > limit {
        return Err(Error("hex"));
    }
    let mut out = Vec::new();
    out.try_reserve(value.len() / 2).map_err(|_| Error("allocation"))?;
    for pair in value.as_bytes().chunks_exact(2) {
        let mut byte = 0;
        for &c in pair {
            byte = byte * 16
                + match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    _ => return Err(Error("hex")),
                };
        }
        out.push(byte);
    }
    Ok(out)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}
fn request_id(method: u8, raw: &[u8]) -> Result<Hash, Error> {
    match method {
        1 => Ok([0; 32]),
        5 => Ok(decode::<SignRequest>(raw)?.request_id),
        6 => Ok(decode::<ResultRequest>(raw)?.request_id),
        _ => {
            let mut bytes = vec![method];
            bytes.extend_from_slice(raw);
            digest("api-request", &bytes)
        }
    }
}
fn validate_frame(frame: &TransportFrame) -> Result<(), Error> {
    if frame.error && !frame.response {
        return Err(Error("result-or-error"));
    }
    validate_api_binary(frame.method, frame.response, frame.error, &frame.payload)?;
    if !frame.response && request_id(frame.method, &frame.payload)? != frame.request_id {
        return Err(Error("request-correlation"));
    }
    if frame.error {
        let e = decode::<ApiError>(&frame.payload)?;
        if e.request_id != frame.request_id || e.method != frame.method {
            return Err(Error("error-correlation"));
        }
        if !(1..=14).contains(&e.code) || e.request_state > 4 {
            return Err(Error("error-code"));
        }
        let read = matches!(frame.method, 1 | 2 | 6 | 8..=15);
        if e.retryable != u8::from(read && (10..=12).contains(&e.code)) {
            return Err(Error("error-retry"));
        }
        std::str::from_utf8(&e.message).map_err(|_| Error("error-message"))?;
    }
    Ok(())
}
pub fn decode_transport_frame(
    raw: &[u8],
    method: u8,
    response: bool,
    expected: Option<&Hash>,
) -> Result<TransportFrame, Error> {
    if raw.len() > 4_194_304 {
        return Err(Error("transport-bound"));
    }
    let fields = Json { raw, pos: 0 }.parse()?;
    let required: &[&str] = if response {
        &["api_version", "request_id", "result", "error"]
    } else {
        &["api_version", "request_id", "request"]
    };
    if fields.len() != required.len()
        || required.iter().any(|k| !fields.contains_key(*k))
        || fields.get("api_version").and_then(|x| x.as_deref()) != Some("1")
    {
        return Err(Error("transport-fields"));
    }
    let field = |key: &str| fields.get(key).and_then(|x| x.as_deref());
    let request_id: Hash =
        unhex(field("request_id"), 32)?.try_into().map_err(|_| Error("hex-width"))?;
    if expected.is_some_and(|id| id != &request_id) {
        return Err(Error("response-correlation"));
    }
    if response && field("result").is_some() == field("error").is_some() {
        return Err(Error("result-or-error"));
    }
    let error = response && field("error").is_some();
    let payload = unhex(
        field(if response {
            if error {
                "error"
            } else {
                "result"
            }
        } else {
            "request"
        }),
        2_000_000,
    )?;
    let frame = TransportFrame { method, request_id, payload, response, error };
    validate_frame(&frame)?;
    Ok(frame)
}
pub fn encode_transport_frame(frame: &TransportFrame) -> Result<String, Error> {
    validate_frame(frame)?;
    let mut out = format!("{{\"api_version\":\"1\",\"request_id\":\"{}\",", hex(&frame.request_id));
    out.push_str(if frame.response {
        if frame.error {
            "\"result\":null,\"error\":\""
        } else {
            "\"error\":null,\"result\":\""
        }
    } else {
        "\"request\":\""
    });
    out.push_str(&hex(&frame.payload));
    out.push_str("\"}");
    if out.len() > 4_194_304 {
        return Err(Error("transport-bound"));
    }
    Ok(out)
}
