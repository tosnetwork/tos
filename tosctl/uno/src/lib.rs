//! `tosctl-uno` — foundation library for the Uno Workchain (wc=2) wallet CLI.
//!
//! Design doc: `doc/uno-workchain.md`, §13 P.6. See [README.md](../README.md)
//! for end-user usage.
//!
//! # Scope (P.6 foundation)
//!
//! This crate implements the **receiver** side of a v1 Uno wallet:
//! deterministic seed derivation from the main TOS BIP-39 mnemonic (§2.6),
//! diversified-address construction (§2.6), compact-filter wallet sync
//! (§5.8), and hybrid-KEM trial-decrypt of scan hits (§2.7 / §7.5). The
//! sender-side `send` command requires the full P.2 Transfer AIR and is
//! NOT in this foundation build.
//!
//! The modules below are scaffolded empty in this commit and filled in by
//! the subsequent commits on this branch:
//!
//! - `poseidon2` / `keygen` — seed + key hierarchy (§2.6 commit).
//! - `address`             — diversified address build + string encoding.
//! - `hybrid_kem` / `gcs` / `wire` / `scan` / `balance` — scan pipeline.
//! - `rpc_client`          — async `uno_*` JSON-RPC client (§9).

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(rust_2018_idioms)]

pub mod address;
pub mod balance;
pub mod boc_decode;
pub mod boc_encode;
pub mod gcs;
pub mod genesis_build;
pub mod hybrid_kem;
pub mod keygen;
pub mod poseidon2;
pub mod rpc_client;
pub mod scan;
pub mod schnorr;
pub mod send;
pub mod transfer;
pub mod wire;

/// Crate version string embedded in the `--version` flag.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Domain-separation tags used throughout the key hierarchy (§2.6).
pub mod tags {
    pub const UNO_SEED_V1: &[u8] = b"uno-seed-v1";
    pub const UNO_OVK_V1: &[u8] = b"uno-ovk-v1";
    pub const UNO_MLKEM_V1: &[u8] = b"uno-mlkem-v1";
    pub const UNO_ESK_V1: &[u8] = b"uno-esk-v1";
    pub const UNO_NK_V1: &[u8] = b"uno-nk-v1";
    pub const UNO_NF_V1: &[u8] = b"uno-nf-v1";
    pub const UNO_IVK_V1: &[u8] = b"uno-ivk-v1";
    pub const UNO_IVK_CM_V1: &[u8] = b"uno-ivk-cm-v1";
    pub const UNO_DIVERSIFIER_V1: &[u8] = b"uno-diversifier-v1";
    pub const UNO_FILTER_V1: &[u8] = b"uno-filter-v1";
    pub const UNO_HYBRID_KEM_V1: &[u8] = b"uno-hybrid-kem-v1";
    pub const UNO_NONCE_V1: &[u8] = b"uno-nonce-v1";
}

/// Common sizes (in bytes) used across modules.
pub mod sizes {
    pub const UNO_SEED: usize = 32;
    pub const RISTRETTO_POINT: usize = 32;
    pub const DIVERSIFIER: usize = 11;
    pub const DIGEST: usize = 32;
    pub const IVK_COMMITMENT: usize = 32;
    pub const MLKEM768_PK: usize = 1184;
    pub const MLKEM768_SK: usize = 2400;
    pub const MLKEM768_CT: usize = 1088;
    pub const ADDRESS: usize = DIVERSIFIER + RISTRETTO_POINT + IVK_COMMITMENT + MLKEM768_PK;
    pub const AEAD_KEY: usize = 32;
    pub const AEAD_NONCE: usize = 12;
}
