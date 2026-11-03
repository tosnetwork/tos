// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Onion-only TCP through a separately supervised local Tor daemon.
//!
//! A bounded SOCKS5 adapter, not an onion-routing implementation. No
//! resolver, environment proxy, redirect, retry or direct fallback exists
//! here. The daemon must enable `IsolateSOCKSAuth`: the random credentials
//! select a circuit isolation group; they authenticate nothing.
use crate::onion::OnionEndpoint;
use anyhow::{bail, ensure, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout_at, Instant},
};

/// One isolation context per relay session, persisted with the session so a
/// later status read uses the same circuit group and no other.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Isolation {
    pub user: String,
    pub password: String,
}

impl Isolation {
    pub fn random() -> Self {
        let mut user = [0u8; 16];
        let mut password = [0u8; 16];
        OsRng.fill_bytes(&mut user);
        OsRng.fill_bytes(&mut password);
        Self { user: hex::encode(user), password: hex::encode(password) }
    }

    fn validate(&self) -> Result<()> {
        for text in [&self.user, &self.password] {
            ensure!(
                !text.is_empty() && text.len() <= 255 && text.is_ascii(),
                "SOCKS isolation credential width"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TorProxy {
    port: u16,
    isolation: Isolation,
}

/// Reads exactly `count` bytes before the deadline.
async fn read_exact(stream: &mut TcpStream, count: usize, deadline: Instant) -> Result<Vec<u8>> {
    let mut data = vec![0u8; count];
    match timeout_at(deadline, stream.read_exact(&mut data)).await {
        Ok(Ok(_)) => Ok(data),
        Ok(Err(_)) => bail!("incomplete Tor SOCKS reply"),
        Err(_) => bail!("Tor SOCKS deadline exceeded"),
    }
}

async fn write_all(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    match timeout_at(deadline, stream.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => bail!("Tor SOCKS write failed: {error}"),
        Err(_) => bail!("Tor SOCKS deadline exceeded"),
    }
}

impl TorProxy {
    /// The local daemon's SOCKS port (1024..=65535) and this session's
    /// isolation identity.
    pub fn new(port: u16, isolation: Isolation) -> Result<Self> {
        ensure!(port >= 1024, "Tor SOCKS port out of range");
        isolation.validate()?;
        Ok(Self { port, isolation })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn isolation(&self) -> &Isolation {
        &self.isolation
    }

    /// A stream to the onion service, through the daemon, under one deadline
    /// for connect, negotiation and the connect reply.
    pub async fn connect(&self, endpoint: &OnionEndpoint, deadline: Instant) -> Result<TcpStream> {
        // Revalidate even when the caller built the endpoint elsewhere.
        let endpoint = OnionEndpoint::parse(&endpoint.origin())?;
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));
        let mut stream = match timeout_at(deadline, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => bail!("Tor SOCKS listener unavailable: {error}"),
            Err(_) => bail!("Tor SOCKS deadline exceeded"),
        };
        write_all(&mut stream, b"\x05\x01\x02", deadline).await?;
        ensure!(
            read_exact(&mut stream, 2, deadline).await? == b"\x05\x02",
            "Tor SOCKS isolation authentication required"
        );
        let user = self.isolation.user.as_bytes();
        let password = self.isolation.password.as_bytes();
        let mut credentials = vec![1u8, u8::try_from(user.len())?];
        credentials.extend_from_slice(user);
        credentials.push(u8::try_from(password.len())?);
        credentials.extend_from_slice(password);
        write_all(&mut stream, &credentials, deadline).await?;
        ensure!(
            read_exact(&mut stream, 2, deadline).await? == b"\x01\x00",
            "Tor SOCKS authentication refused"
        );
        let host = endpoint.host().as_bytes();
        let mut request = vec![5u8, 1, 0, 3, u8::try_from(host.len())?];
        request.extend_from_slice(host);
        request.extend_from_slice(&endpoint.port().to_be_bytes());
        write_all(&mut stream, &request, deadline).await?;
        let reply = read_exact(&mut stream, 4, deadline).await?;
        ensure!(&reply[..3] == b"\x05\x00\x00", "Tor onion connection unavailable");
        let size = match reply[3] {
            1 => 4,
            4 => 16,
            3 => {
                let size = usize::from(read_exact(&mut stream, 1, deadline).await?[0]);
                ensure!(size != 0, "invalid Tor SOCKS bound address");
                size
            }
            _ => bail!("invalid Tor SOCKS address type"),
        };
        read_exact(&mut stream, size + 2, deadline).await?;
        Ok(stream)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::onion::tests::{ONION, ORIGIN};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    pub(crate) type Seen<T> = Arc<Mutex<Vec<T>>>;

    /// What the fake peer answers at each step and what it saw.
    #[derive(Clone)]
    pub(crate) struct Peer {
        pub method: Vec<u8>,
        pub auth: Vec<u8>,
        pub reply: Vec<u8>,
        pub credentials: Seen<(Vec<u8>, Vec<u8>)>,
        pub targets: Seen<(String, u16)>,
    }

    impl Default for Peer {
        fn default() -> Self {
            Self {
                method: b"\x05\x02".to_vec(),
                auth: b"\x01\x00".to_vec(),
                reply: b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec(),
                credentials: Arc::default(),
                targets: Arc::default(),
            }
        }
    }

    /// Runs the SOCKS negotiation with one client as the Python test peer
    /// does, fragmenting the connect reply byte by byte; returns the stream
    /// once connected, or `None` when the peer stopped the handshake.
    pub(crate) async fn negotiate(peer: &Peer, mut stream: TcpStream) -> Result<Option<TcpStream>> {
        let mut head = [0u8; 3];
        stream.read_exact(&mut head).await?;
        ensure!(head == *b"\x05\x01\x02", "client did not require SOCKS authentication");
        stream.write_all(&peer.method).await?;
        if peer.method != b"\x05\x02" {
            return Ok(None);
        }
        let mut version = [0u8; 1];
        stream.read_exact(&mut version).await?;
        ensure!(version[0] == 1, "wrong authentication version");
        let mut len = [0u8; 1];
        stream.read_exact(&mut len).await?;
        let mut user = vec![0u8; usize::from(len[0])];
        stream.read_exact(&mut user).await?;
        stream.read_exact(&mut len).await?;
        let mut password = vec![0u8; usize::from(len[0])];
        stream.read_exact(&mut password).await?;
        peer.credentials.lock().map_err(|_| anyhow::anyhow!("lock"))?.push((user, password));
        stream.write_all(&peer.auth).await?;
        if peer.auth != b"\x01\x00" {
            return Ok(None);
        }
        let mut connect = [0u8; 4];
        stream.read_exact(&mut connect).await?;
        ensure!(
            connect == *b"\x05\x01\x00\x03",
            "client resolved destination instead of sending domain"
        );
        stream.read_exact(&mut len).await?;
        let mut host = vec![0u8; usize::from(len[0])];
        stream.read_exact(&mut host).await?;
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        peer.targets
            .lock()
            .map_err(|_| anyhow::anyhow!("lock"))?
            .push((String::from_utf8(host)?, u16::from_be_bytes(port)));
        for byte in &peer.reply {
            stream.write_all(&[*byte]).await?;
            stream.flush().await?;
        }
        if &peer.reply[..3] != b"\x05\x00\x00" || ![1u8, 3, 4].contains(&peer.reply[3]) {
            return Ok(None);
        }
        Ok(Some(stream))
    }

    /// A listener that negotiates once per connection and then hands the
    /// stream to `serve`.
    pub(crate) async fn listen<F, Fut>(peer: Peer, serve: F) -> Result<u16>
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let serve = Arc::new(serve);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let peer = peer.clone();
                let serve = serve.clone();
                tokio::spawn(async move {
                    if let Ok(Some(stream)) = negotiate(&peer, stream).await {
                        serve(stream).await;
                    }
                });
            }
        });
        Ok(port)
    }

    #[tokio::test]
    async fn handshake_sends_the_domain_and_uses_the_session_identity() -> Result<()> {
        let peer = Peer::default();
        let port = listen(peer.clone(), |_stream| async {}).await?;
        let isolation = Isolation::random();
        let proxy = TorProxy::new(port, isolation.clone())?;
        let endpoint = OnionEndpoint::parse(&format!("{ORIGIN}:8080"))?;
        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        proxy.connect(&endpoint, deadline).await?;
        proxy.connect(&endpoint, deadline).await?;
        let other = TorProxy::new(port, Isolation::random())?;
        other.connect(&endpoint, deadline).await?;
        let credentials = peer.credentials.lock().map_err(|_| anyhow::anyhow!("lock"))?.clone();
        assert_eq!(credentials.len(), 3);
        assert_eq!(credentials[0], credentials[1]);
        assert_ne!(credentials[0], credentials[2]);
        assert_eq!(credentials[0].0, isolation.user.as_bytes());
        let targets = peer.targets.lock().map_err(|_| anyhow::anyhow!("lock"))?.clone();
        assert_eq!(targets, vec![(ONION.to_owned(), 8080); 3]);
        Ok(())
    }

    #[tokio::test]
    async fn no_downgrade_auth_failure_or_connect_failure_passes() -> Result<()> {
        let deadline = || Instant::now() + std::time::Duration::from_secs(3);
        let endpoint = OnionEndpoint::parse(ORIGIN)?;
        for (method, auth, reply, message, targets) in [
            (
                b"\x05\x00".to_vec(),
                b"\x01\x00".to_vec(),
                Vec::new(),
                "isolation authentication required",
                0,
            ),
            (b"\x05\x02".to_vec(), b"\x01\x01".to_vec(), Vec::new(), "authentication refused", 0),
            (
                b"\x05\x02".to_vec(),
                b"\x01\x00".to_vec(),
                b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00".to_vec(),
                "onion connection unavailable",
                1,
            ),
            (
                b"\x05\x02".to_vec(),
                b"\x01\x00".to_vec(),
                b"\x05\x00\x00\x09".to_vec(),
                "address type",
                1,
            ),
            (
                b"\x05\x02".to_vec(),
                b"\x01\x00".to_vec(),
                b"\x05\x00\x00\x03\x00".to_vec(),
                "bound address",
                1,
            ),
        ] {
            let peer = Peer {
                method,
                auth,
                reply: if reply.is_empty() { Peer::default().reply } else { reply },
                ..Peer::default()
            };
            let port = listen(peer.clone(), |_stream| async {}).await?;
            let error = TorProxy::new(port, Isolation::random())?
                .connect(&endpoint, deadline())
                .await
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(error.contains(message), "{error}");
            assert_eq!(peer.targets.lock().map_err(|_| anyhow::anyhow!("lock"))?.len(), targets);
        }
        Ok(())
    }

    #[tokio::test]
    async fn ipv6_and_domain_bound_replies_are_consumed() -> Result<()> {
        let endpoint = OnionEndpoint::parse(ORIGIN)?;
        for reply in [
            [b"\x05\x00\x00\x04".to_vec(), vec![0u8; 18]].concat(),
            b"\x05\x00\x00\x03\x03abc\x00\x00".to_vec(),
        ] {
            let peer = Peer { reply, ..Peer::default() };
            let port = listen(peer, |mut stream| async move {
                let _ = stream.write_all(b"ok").await;
            })
            .await?;
            let mut stream = TorProxy::new(port, Isolation::random())?
                .connect(&endpoint, Instant::now() + std::time::Duration::from_secs(3))
                .await?;
            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await?;
            assert_eq!(&answer, b"ok");
        }
        Ok(())
    }

    #[tokio::test]
    async fn one_deadline_across_a_fragmented_handshake_and_no_listener() -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 3];
                let _ = stream.read_exact(&mut head).await;
                let _ = stream.write_all(b"\x05").await;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
        let started = Instant::now();
        let error = TorProxy::new(port, Isolation::random())?
            .connect(
                &OnionEndpoint::parse(ORIGIN)?,
                started + std::time::Duration::from_millis(200),
            )
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains("deadline"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_millis(1500));
        // A port nobody listens on: unavailable, and nothing else is tried.
        let closed = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = closed.local_addr()?.port();
        drop(closed);
        let error = TorProxy::new(port, Isolation::random())?
            .connect(
                &OnionEndpoint::parse(ORIGIN)?,
                Instant::now() + std::time::Duration::from_secs(1),
            )
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains("listener unavailable"), "{error}");
        assert!(TorProxy::new(80, Isolation::random()).is_err());
        assert!(
            TorProxy::new(9050, Isolation { user: String::new(), password: "x".into() }).is_err()
        );
        Ok(())
    }
}
