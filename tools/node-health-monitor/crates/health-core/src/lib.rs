//! Bounded deterministic monitoring logic. This crate has no network client.
pub mod broker;
pub mod config;
pub mod duty;
pub mod evidence;
pub mod guard;
pub mod incident;
pub mod observer;
pub mod query;
pub mod query_output;
pub mod source;

pub mod contracts;
pub mod diagnosis;
pub mod freshness;
pub mod health_state;
pub mod rules;
pub mod wire;

pub mod consensus_v2;
pub mod native;

pub mod edge_snapshot;
