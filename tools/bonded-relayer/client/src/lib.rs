// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! The wallet side of the BR1 bonded-relayer protocol.
//!
//! One implementation of the wire contract for both ends: the native provider
//! depends on this crate for the canonical JSON rules, the release scope, the
//! request object and its structural checks, the Bond identity and quote
//! authentication, so a request a wallet builds is checked by the same code
//! the provider will run on it. On top of that, for the wallet only: the
//! onion endpoint, the SOCKS5 adapter to a local Tor daemon, the bounded
//! HTTP/1.1 exchange and the quote/submit/status client.
//!
//! What this crate does not do: hold keys or notes, keep a journal, read the
//! chain, retry, or fall back to any other transport. A relayer's status
//! answer is its claim; only the wallet's own verified chain reads settle a
//! spend.

pub mod bond;
pub mod client;
pub mod http;
pub mod onion;
pub mod quote;
pub mod release;
pub mod request;
pub mod socks;
pub mod wire;
