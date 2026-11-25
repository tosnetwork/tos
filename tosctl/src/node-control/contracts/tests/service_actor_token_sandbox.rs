/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The token-rail Service Actor (crypto/smartcont/service-actor-token-code.fc)
//! on the token bridge's sandbox network, with the real bridge, minter and
//! wallets.
//!
//! Every message is delivered through the executor one at a time, so a test
//! can lose, hold, reorder or forge any of them and change prices or the
//! configuration between legs. After every delivered message the actor's
//! token invariant is checked (service_actor_token/world.rs), and the bridge
//! model checks supply and balance conservation. With TOKEN_BRIDGE_TRACE_DIR
//! set every transaction is recorded and scripts/replay-token-bridge-trace.py
//! replays it in the native engine, gas included.
//!
//! The suite ports every case of the native actor's sandbox
//! (service_actor_sandbox.rs) and covers the token rail's own cases (USDC
//! settlement design, section 8, T3).

#[path = "fixtures/current_network.rs"]
mod current_network;

#[path = "token_bridge/harness.rs"]
mod harness;
#[path = "token_bridge/model.rs"]
mod model;
#[path = "token_bridge/state.rs"]
mod state;

#[path = "service_actor_token/world.rs"]
mod world;

#[path = "service_actor_token/lifecycle.rs"]
mod lifecycle;
