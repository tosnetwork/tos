// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! One bounded HTTP/1.1 exchange on a stream that is already connected: one
//! POST, one response, the connection closed. The same framing rules the BR1
//! service enforces on what it receives are enforced here on what it sends
//! back; anything else is "unavailable", never interpreted.
use std::collections::BTreeMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout_at, Instant},
};

pub const HEADER_LIMIT: usize = 8192;
pub const RESPONSE_LIMIT: usize = 64 * 1024;
const MAX_HEADER_LINES: usize = 33;
const MAX_START_LINE: usize = 256;

/// The relayer answered with a status line and a body within the bounds.
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why no answer was obtained. `Malformed` covers everything that is not a
/// well-formed, in-bounds HTTP/1.1 response: it is not an answer from the
/// relayer.
#[derive(Debug)]
pub enum HttpError {
    Deadline,
    Closed,
    Malformed(&'static str),
    Io(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Deadline => write!(f, "HTTP deadline exceeded"),
            HttpError::Closed => write!(f, "incomplete HTTP response"),
            HttpError::Malformed(what) => write!(f, "{what}"),
            HttpError::Io(what) => write!(f, "HTTP transport failed: {what}"),
        }
    }
}
impl std::error::Error for HttpError {}

fn token(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Reads one response head and body from `stream`: the headers complete
/// within the limit, at most 33 lines, ASCII, token names, no duplicates, no
/// control characters, no alternate framing, exactly one canonical
/// Content-Length at most `maximum`, `application/json` when there is a body,
/// and not one byte beyond the body.
pub async fn receive(
    stream: &mut TcpStream,
    maximum: usize,
    deadline: Instant,
) -> Result<(String, BTreeMap<String, String>, Vec<u8>), HttpError> {
    let mut data: Vec<u8> = Vec::with_capacity(4096);
    let split = loop {
        if let Some(position) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            if position > HEADER_LIMIT {
                return Err(HttpError::Malformed("HTTP headers too large"));
            }
            break position;
        }
        if data.len() >= HEADER_LIMIT + 4 {
            return Err(HttpError::Malformed("HTTP headers too large"));
        }
        let mut chunk = vec![0u8; (HEADER_LIMIT + 4 - data.len()).min(4096)];
        let read = match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => return Err(HttpError::Io(error.to_string())),
            Err(_) => return Err(HttpError::Deadline),
        };
        if read == 0 {
            return Err(HttpError::Closed);
        }
        data.extend_from_slice(&chunk[..read]);
    };
    let head = &data[..split];
    let lines: Vec<&[u8]> =
        head.split(|b| *b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).collect();
    // `split` on "\n" of a head whose lines end in "\r\n": every line keeps
    // its "\r", stripped above; a bare "\n" would leave a line without one,
    // which is a malformed line below because its "\r" would be inside it.
    if head.windows(1).filter(|w| w == b"\n").count() + 1 != lines.len()
        || head.iter().filter(|b| **b == b'\r').count() != lines.len() - 1
    {
        return Err(HttpError::Malformed("malformed HTTP header"));
    }
    if lines.len() > MAX_HEADER_LINES || lines[0].len() > MAX_START_LINE {
        return Err(HttpError::Malformed("HTTP header count or request line limit"));
    }
    if !head.is_ascii() {
        return Err(HttpError::Malformed("non-ASCII HTTP headers"));
    }
    let start = String::from_utf8_lossy(lines[0]).into_owned();
    let mut headers = BTreeMap::new();
    for line in &lines[1..] {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            return Err(HttpError::Malformed("malformed HTTP header"));
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if !token(name) {
            return Err(HttpError::Malformed("malformed HTTP header"));
        }
        let key = String::from_utf8_lossy(name).to_ascii_lowercase();
        let text = String::from_utf8_lossy(value).trim_matches([' ', '\t']).to_owned();
        if headers.contains_key(&key) || text.bytes().any(|b| b < 32 || b == 127) {
            return Err(HttpError::Malformed("duplicate or invalid HTTP header"));
        }
        headers.insert(key, text);
    }
    if ["transfer-encoding", "content-encoding", "expect", "upgrade"]
        .iter()
        .any(|k| headers.contains_key(*k))
    {
        return Err(HttpError::Malformed("unsupported HTTP framing"));
    }
    let length = match headers.get("content-length") {
        Some(text) => text.as_str(),
        None if start.starts_with("GET ") => "0",
        None => return Err(HttpError::Malformed("one canonical Content-Length is required")),
    };
    let canonical = length == "0"
        || (!length.is_empty()
            && length.len() <= 8
            && !length.starts_with('0')
            && length.bytes().all(|b| b.is_ascii_digit()));
    if !canonical {
        return Err(HttpError::Malformed("one canonical Content-Length is required"));
    }
    let length: usize = length
        .parse()
        .map_err(|_| HttpError::Malformed("one canonical Content-Length is required"))?;
    if length > maximum {
        return Err(HttpError::Malformed("HTTP body too large"));
    }
    if length > 0 && headers.get("content-type").map(String::as_str) != Some("application/json") {
        return Err(HttpError::Malformed("application/json required"));
    }
    let mut body = data[split + 4..].to_vec();
    if body.len() > length {
        return Err(HttpError::Malformed("HTTP pipelining is not supported"));
    }
    while body.len() < length {
        let mut chunk = vec![0u8; (length - body.len()).min(65536)];
        let read = match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => return Err(HttpError::Io(error.to_string())),
            Err(_) => return Err(HttpError::Deadline),
        };
        if read == 0 {
            return Err(HttpError::Closed);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok((start, headers, body))
}

/// One POST of a JSON body and its response. The status is a three-digit
/// code in 100..=599 from an `HTTP/1.1` status line; anything else is
/// malformed. The body is at most `RESPONSE_LIMIT` bytes of JSON.
pub async fn exchange(
    stream: &mut TcpStream,
    authority: &str,
    path: &str,
    body: &[u8],
    deadline: Instant,
) -> Result<Response, HttpError> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut wire = head.into_bytes();
    wire.extend_from_slice(body);
    match timeout_at(deadline, stream.write_all(&wire)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(HttpError::Io(error.to_string())),
        Err(_) => return Err(HttpError::Deadline),
    }
    let (line, _, body) = receive(stream, RESPONSE_LIMIT, deadline).await?;
    let status = status_code(&line)
        .ok_or(HttpError::Malformed("relayer returned a malformed status line"))?;
    Ok(Response { status, body })
}

/// The status of an `HTTP/1.1` status line: exactly `HTTP/1.1 ddd phrase`
/// with a code in 100..=599. Anything else is not an answer.
pub fn status_code(line: &str) -> Option<u16> {
    let mut parts = line.splitn(3, ' ');
    let (version, code, _phrase) = (parts.next()?, parts.next()?, parts.next()?);
    if version != "HTTP/1.1"
        || code.len() != 3
        || !code.bytes().all(|b| b.is_ascii_digit())
        || !matches!(code.as_bytes().first(), Some(b'1'..=b'5'))
    {
        return None;
    }
    code.parse().ok()
}

/// Writes one JSON response the way the BR1 service does, for peers in tests.
pub fn response_bytes(status: u16, phrase: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\
         Connection: close\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn ensure_ok() -> anyhow::Result<()> {
        Ok(())
    }

    /// A server that answers every connection with `answer`, after reading the
    /// request head, and returns what it read.
    async fn answering(
        answer: Vec<u8>,
    ) -> anyhow::Result<(u16, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let answer = answer.clone();
                let record = record.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 65536];
                    let mut read_total = Vec::new();
                    while let Ok(read) = stream.read(&mut buffer).await {
                        read_total.extend_from_slice(&buffer[..read]);
                        if read == 0 || read_total.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    if let Ok(mut seen) = record.lock() {
                        seen.push(read_total);
                    }
                    let _ = stream.write_all(&answer).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok((port, seen))
    }

    async fn post(port: u16) -> Result<Response, HttpError> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| HttpError::Io(e.to_string()))?;
        exchange(
            &mut stream,
            "x.onion",
            "/v1/quote",
            b"{}",
            Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
    }

    #[tokio::test]
    async fn a_well_formed_answer_is_returned_with_its_status() -> anyhow::Result<()> {
        let (port, seen) = answering(response_bytes(202, "Accepted", br#"{"a":1}"#)).await?;
        let response = post(port).await?;
        assert_eq!((response.status, response.body.as_slice()), (202, &br#"{"a":1}"#[..]));
        let seen = seen.lock().map_err(|_| anyhow::anyhow!("lock"))?.clone();
        let head = String::from_utf8_lossy(&seen[0]).into_owned();
        assert!(head.starts_with("POST /v1/quote HTTP/1.1\r\nHost: x.onion\r\n"), "{head}");
        assert!(head.contains("Connection: close\r\n") && head.ends_with("\r\n\r\n{}"), "{head}");
        for status in [429u16, 503] {
            let (port, _) =
                answering(response_bytes(status, "Refused", br#"{"error":"busy"}"#)).await?;
            assert_eq!(post(port).await?.status, status);
        }
        ensure_ok()
    }

    #[tokio::test]
    async fn malformed_answers_are_unavailable_not_answers() -> anyhow::Result<()> {
        let body = br#"{"error":"busy"}"#;
        let plain = |line: &str| {
            format!(
                "{line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes()
            .into_iter()
            .chain(body.iter().copied())
            .collect::<Vec<u8>>()
        };
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (plain("HTTP/1.1 4x9 Odd"), "malformed status line"),
            (plain("HTTP/1.0 429 Old"), "malformed status line"),
            (plain("HTTP/1.1 999 High"), "malformed status line"),
            (plain("HTTP/1.1 429"), "malformed status line"),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(), "unsupported HTTP framing"),
            (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".to_vec(), "unsupported HTTP framing"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".to_vec(), "Content-Length is required"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(), "duplicate or invalid HTTP header"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 02\r\n\r\n{}".to_vec(), "Content-Length is required"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 123456789\r\n\r\n".to_vec(), "Content-Length is required"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99999999\r\n\r\n".to_vec(), "HTTP body too large"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}".to_vec(), "application/json required"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}{}".to_vec(), "pipelining"),
            (b"HTTP/1.1 200 OK\r\nBad Header\r\nContent-Length: 0\r\n\r\n".to_vec(), "malformed HTTP header"),
            (b"HTTP/1.1 200 OK\r\nX-Odd: a\x01b\r\nContent-Length: 0\r\n\r\n".to_vec(), "duplicate or invalid HTTP header"),
            (b"HTTP/1.1 200 OK\r\nX-Odd: \xc3\xa9\r\nContent-Length: 0\r\n\r\n".to_vec(), "non-ASCII HTTP headers"),
            (b"HTTP/1.1 200 OK\nContent-Length: 0\n\r\n\r\n".to_vec(), "malformed HTTP header"),
            (b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid\r\nContent-Length: 0\r\n\r\n".to_vec(), "redirect"),
            ({
                let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
                for i in 0..33 {
                    many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
                }
                many.extend_from_slice(b"\r\n");
                many
            }, "header count"),
            ({
                let mut big = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
                big.extend(vec![b'a'; HEADER_LIMIT]);
                big.extend_from_slice(b"\r\n\r\n");
                big
            }, "headers too large"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{}".to_vec(), "incomplete"),
            (Vec::new(), "incomplete"),
        ];
        for (answer, expected) in cases {
            let (port, _) = answering(answer.clone()).await?;
            let result = post(port).await;
            if expected == "redirect" {
                // A redirect is a well-formed non-2xx answer: reported with its
                // status, never followed.
                assert_eq!(result.map(|r| r.status).ok(), Some(302));
                continue;
            }
            let error = result.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(
                error.contains(expected),
                "{expected}: got {error:?} for {:?}",
                String::from_utf8_lossy(&answer)
            );
        }
        ensure_ok()
    }

    #[tokio::test]
    async fn trickled_headers_and_a_stalled_body_hit_the_one_deadline() -> anyhow::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{" {
                        if stream.write_all(&[*byte]).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                });
            }
        });
        let started = Instant::now();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let error = exchange(
            &mut stream,
            "x.onion",
            "/v1/status",
            b"{}",
            started + std::time::Duration::from_millis(600),
        )
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(error.contains("deadline"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_millis(1500));
        ensure_ok()
    }
}
