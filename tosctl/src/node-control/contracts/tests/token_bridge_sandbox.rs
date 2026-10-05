/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The token bridge's settlement protocol across the bridge, its minters and
//! wallets, with real action and bounce phases.
//!
//! Every message is delivered through the executor one at a time, so a test can
//! lose, duplicate, hold, reorder or forge any of them, change prices and the
//! configuration between legs, delete and recreate accounts, and then recover
//! with funded retransmission. An independent model (token_bridge/model.rs)
//! checks every transaction. With TOKEN_BRIDGE_TRACE_DIR set every transaction
//! is recorded and scripts/replay-token-bridge-trace.py replays it in the
//! native engine. The test names refer to the matrix in
//! crosschain/token-bridge/SETTLEMENT-PROTOCOL.md.

#[path = "token_bridge/harness.rs"]
mod harness;
#[path = "token_bridge/model.rs"]
mod model;
#[path = "token_bridge/mint.rs"]
mod mint;
#[path = "token_bridge/burn.rs"]
mod burn;
#[path = "token_bridge/state.rs"]
mod state;
#[path = "token_bridge/extended.rs"]
mod extended;
#[path = "token_bridge/windows.rs"]
mod windows;
#[path = "token_bridge/recovery.rs"]
mod recovery;
#[path = "token_bridge/lifecycle.rs"]
mod lifecycle;
#[path = "token_bridge/source.rs"]
mod source;
