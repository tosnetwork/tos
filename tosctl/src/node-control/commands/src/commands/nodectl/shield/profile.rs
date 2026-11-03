/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Which pool this client talks to, and what it must look like.
//!
//! A profile names one pool on one network. Everything else about the pool --
//! its code, its frozen configuration, the verifying key it checks proofs
//! against -- is read from the chain and compared with the pins this tool
//! carries. A pool that matches none of them is not a pool this client knows
//! how to use, and an unknown pool is refused rather than guessed at.

use anyhow::Context;
use chain_block::MsgAddressInt;
use contracts::shielded_pool::PoolState;
use sha2::{Digest, Sha256};
use std::path::Path;

pub const PROFILE_SCHEMA: &str = "tosctl-shield-profile-v1";

/// The largest profile file this tool reads.
const MAX_PROFILE_BYTES: u64 = 16 * 1024;

/// A pool on a network, as the operator names it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub schema: String,
    pub global_id: i32,
    /// The pool account, `workchain:hex`.
    pub pool_address: String,
    /// The hash of the pool's code cell, hex.
    pub pool_code_hash: String,
}

impl Profile {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let meta =
            std::fs::metadata(path).with_context(|| format!("read profile {}", path.display()))?;
        anyhow::ensure!(meta.is_file(), "profile {} is not a regular file", path.display());
        anyhow::ensure!(meta.len() <= MAX_PROFILE_BYTES, "profile {} is too large", path.display());
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read profile {}", path.display()))?;
        let profile: Self = serde_json::from_str(&text)
            .with_context(|| format!("parse profile {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema == PROFILE_SCHEMA,
            "profile schema {:?} is not {PROFILE_SCHEMA}",
            self.schema
        );
        let address = self.address()?;
        anyhow::ensure!(address.workchain_id() == 0, "the pool lives in workchain 0");
        anyhow::ensure!(
            !address.is_masterchain() && address.address().remaining_bits() == 256,
            "the pool address is a standard workchain-0 address"
        );
        self.code_hash()?;
        Network::of(self.global_id)?;
        Ok(())
    }

    pub fn address(&self) -> anyhow::Result<MsgAddressInt> {
        self.pool_address.parse::<MsgAddressInt>().context("profile pool_address")
    }

    pub fn code_hash(&self) -> anyhow::Result<[u8; 32]> {
        word(&self.pool_code_hash).context("profile pool_code_hash")
    }

    /// The pool account id, which with the global id fixes the execution
    /// domain every shielded key is scoped to.
    pub fn account_id(&self) -> anyhow::Result<[u8; 32]> {
        let address = self.address()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&address.address().get_bytestring(0));
        Ok(out)
    }
}

/// The network a global id names, and the gate on each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Global id 3: an isolated local network. Allowed by default.
    Local,
    /// Global id 2: the public testnet. Allowed with an explicit flag.
    Testnet,
    /// Global id 1: refused. The pool has no live GO.
    Mainnet,
}

impl Network {
    pub fn of(global_id: i32) -> anyhow::Result<Self> {
        match global_id {
            3 => Ok(Self::Local),
            2 => Ok(Self::Testnet),
            1 => Ok(Self::Mainnet),
            other => anyhow::bail!("global id {other} names no network this client knows"),
        }
    }

    /// Whether this client may act on the network at all.
    pub fn gate(self, allow_testnet_pool: bool) -> anyhow::Result<()> {
        match self {
            Self::Local => Ok(()),
            Self::Testnet if allow_testnet_pool => Ok(()),
            Self::Testnet => anyhow::bail!(
                "the public testnet pool is gated: pass --allow-testnet-pool to use it, and \
                 expect the pool to be reset without notice"
            ),
            Self::Mainnet => anyhow::bail!(
                "the shielded pool is not deployed on the main network and this client refuses \
                 to act on global id 1"
            ),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

/// Where a verifying key came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    /// The finished phase-2 ceremony key. Usable on any permitted network.
    Ceremony,
    /// The development fixture. Usable on an isolated local network only.
    Development,
}

/// Pool code this tool knows, by code-cell hash.
pub const KNOWN_CODE_HASHES: &[&str] =
    &["5528ff26426e36b948bbd6ab3bd6615c82c98c87dd774e4fb456f3965722c466"];

/// Profile documents this tool was written against, by domain-prefixed hash.
pub const KNOWN_PROFILE_HASHES: &[&str] = &[
    // The frozen V16 candidate.
    "ad94219a2db8cb24493754ac6bdf0b9cfff4cb014ebe0d2610650e4631d19beb",
    // The profile revision this tool's codecs were written against.
    "4de5d5c81406f9ce973dd2b7e4026a72750330b757ba7f4c32bdb9edd07ccbec",
];

/// The Poseidon2 parameter manifest, by SHA-256.
pub const KNOWN_POSEIDON_MANIFEST_HASHES: &[&str] =
    &["57ed3c8ac13652a1bdeced6b82a53f20db32d4b02338354178ec160a68e6804c"];

/// Verifying keys, by the SHA-256 of their exact 1248-byte stream, which is
/// also what the pool stores as `groth16_vk_hash`.
pub const KNOWN_VERIFYING_KEYS: &[(KeyClass, &str)] = &[
    (KeyClass::Ceremony, "49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c"),
    (KeyClass::Development, "5b760517f330e3914d76fc5baf18cc9e46f6b03d8467eeafb4de10d9681c9251"),
];

/// What the chain says the pool is.
pub struct ObservedPool<'a> {
    pub code_hash: [u8; 32],
    pub state: &'a PoolState,
}

/// Checks the pool the chain shows against the profile and the pins.
///
/// On the local network the operator deployed the pool themselves, so the
/// code hash they wrote into the profile is the pin; the development key is
/// accepted there and nowhere else. On a public network the code must be code
/// this tool knows. Everywhere, the profile document, the Poseidon manifest
/// and the verifying key -- its recorded hash and its actual bytes -- must be
/// ones this tool was written against.
pub fn check_pins(
    profile: &Profile,
    network: Network,
    observed: &ObservedPool<'_>,
) -> anyhow::Result<()> {
    let expected_code = profile.code_hash()?;
    anyhow::ensure!(
        observed.code_hash == expected_code,
        "the pool's code hash {} is not the profile's {}",
        hex::encode(observed.code_hash),
        hex::encode(expected_code)
    );
    if network != Network::Local {
        anyhow::ensure!(
            is_known(KNOWN_CODE_HASHES, &observed.code_hash)?,
            "the pool's code hash {} is not pool code this client knows",
            hex::encode(observed.code_hash)
        );
    }
    let config = &observed.state.config;
    anyhow::ensure!(
        is_known(KNOWN_PROFILE_HASHES, &config.profile_hash)?,
        "the pool's profile hash {} is not a profile this client was written against",
        hex::encode(config.profile_hash)
    );
    anyhow::ensure!(
        is_known(KNOWN_POSEIDON_MANIFEST_HASHES, &config.poseidon_manifest_hash)?,
        "the pool's Poseidon manifest hash {} is not one this client knows",
        hex::encode(config.poseidon_manifest_hash)
    );
    let actual_vk_hash: [u8; 32] = Sha256::digest(&observed.state.verifying_key).into();
    anyhow::ensure!(
        actual_vk_hash == config.groth16_vk_hash,
        "the pool's stored verifying key hashes to {}, not the {} its configuration records",
        hex::encode(actual_vk_hash),
        hex::encode(config.groth16_vk_hash)
    );
    let class = KNOWN_VERIFYING_KEYS
        .iter()
        .find_map(|(class, pin)| {
            word(pin).ok().filter(|pin| pin == &config.groth16_vk_hash).map(|_| *class)
        })
        .with_context(|| {
            format!(
                "the pool's verifying key {} is not a key this client knows",
                hex::encode(config.groth16_vk_hash)
            )
        })?;
    if class == KeyClass::Development {
        anyhow::ensure!(
            network == Network::Local,
            "the pool verifies proofs against the development key, which is only acceptable on \
             an isolated local network"
        );
    }
    Ok(())
}

fn is_known(pins: &[&str], value: &[u8; 32]) -> anyhow::Result<bool> {
    for pin in pins {
        if &word(pin)? == value {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Thirty-two bytes from lowercase or uppercase hex, and nothing else.
pub fn word(text: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(text.trim()).context("not hex")?;
    let word: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("not 32 bytes"))?;
    Ok(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pin_is_a_well_formed_hash() {
        for pin in KNOWN_CODE_HASHES
            .iter()
            .chain(KNOWN_PROFILE_HASHES)
            .chain(KNOWN_POSEIDON_MANIFEST_HASHES)
            .chain(KNOWN_VERIFYING_KEYS.iter().map(|(_, pin)| pin))
        {
            word(pin).expect("a pin is 32 hex bytes");
        }
    }

    #[test]
    fn the_network_gate_admits_local_gates_testnet_and_refuses_mainnet() {
        assert!(Network::of(3).expect("local").gate(false).is_ok());
        assert!(Network::of(2).expect("testnet").gate(false).is_err());
        assert!(Network::of(2).expect("testnet").gate(true).is_ok());
        assert!(Network::of(1).expect("mainnet").gate(true).is_err());
        assert!(Network::of(7).is_err());
    }

    fn local_profile() -> Profile {
        Profile {
            schema: PROFILE_SCHEMA.to_owned(),
            global_id: 3,
            pool_address: "0:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe"
                .into(),
            pool_code_hash: hex::encode([0x77; 32]),
        }
    }

    fn observed_state() -> PoolState {
        let verifying_key: Vec<u8> = (0..1248u32).map(|i| (i % 251) as u8).collect();
        let vk_hash: [u8; 32] = Sha256::digest(&verifying_key).into();
        PoolState {
            commitment_root: [0; 32],
            commitment_next_index: 0,
            reserved_recovery_leaves: 0,
            nullifier_root: [0; 32],
            nullifier_next_index: 1,
            last_anchor_epoch: u32::MAX,
            native_liability: 0,
            reserve_floor: 1,
            config: contracts::shielded_pool::PoolConfig {
                profile_hash: word(KNOWN_PROFILE_HASHES[0]).expect("pin"),
                poseidon_manifest_hash: word(KNOWN_POSEIDON_MANIFEST_HASHES[0]).expect("pin"),
                groth16_vk_hash: vk_hash,
                withdrawal_fee: 1,
                denominations: vec![1_000_000_000],
            },
            verifying_key,
            anchors: contracts::shielded_pool::AnchorStore::default(),
        }
    }

    #[test]
    fn the_pins_are_checked_field_by_field() {
        let profile = local_profile();
        let state = observed_state();
        let observed = ObservedPool { code_hash: [0x77; 32], state: &state };
        // The fixture key is a known key only once its hash is in the table,
        // so the honest result here is a refusal for an unknown key.
        let error = check_pins(&profile, Network::Local, &observed).expect_err("an unknown key");
        assert!(error.to_string().contains("verifying key"), "{error}");

        // A key the configuration records but the bytes do not match.
        let mut lying = state.clone();
        lying.config.groth16_vk_hash = word(KNOWN_VERIFYING_KEYS[1].1).expect("pin");
        let error = check_pins(
            &profile,
            Network::Local,
            &ObservedPool { code_hash: [0x77; 32], state: &lying },
        )
        .expect_err("bytes that do not hash to the recorded key");
        assert!(error.to_string().contains("hashes to"), "{error}");

        // Other people's code on a public network, and the operator's own
        // code locally.
        let mut testnet = profile.clone();
        testnet.global_id = 2;
        let error =
            check_pins(&testnet, Network::Testnet, &observed).expect_err("unknown code on testnet");
        assert!(error.to_string().contains("pool code"), "{error}");
        let mut other = profile.clone();
        other.pool_code_hash = hex::encode([0x78; 32]);
        let error = check_pins(&other, Network::Local, &observed)
            .expect_err("a code hash not the profile's");
        assert!(error.to_string().contains("code hash"), "{error}");

        // A foreign profile document or Poseidon manifest.
        let mut foreign = state.clone();
        foreign.config.profile_hash = [1; 32];
        assert!(
            check_pins(
                &profile,
                Network::Local,
                &ObservedPool { code_hash: [0x77; 32], state: &foreign }
            )
            .is_err()
        );
        let mut foreign = state;
        foreign.config.poseidon_manifest_hash = [1; 32];
        assert!(
            check_pins(
                &profile,
                Network::Local,
                &ObservedPool { code_hash: [0x77; 32], state: &foreign }
            )
            .is_err()
        );
    }

    #[test]
    fn a_profile_is_validated_on_load() {
        let profile = Profile {
            schema: PROFILE_SCHEMA.to_owned(),
            global_id: 3,
            pool_address: "0:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe"
                .into(),
            pool_code_hash: KNOWN_CODE_HASHES[0].into(),
        };
        profile.validate().expect("a good profile");
        assert_eq!(
            hex::encode(profile.account_id().expect("account id")),
            "aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe"
        );
        let mut bad = profile.clone();
        bad.schema = "something-else".into();
        assert!(bad.validate().is_err(), "a foreign schema");
        let mut bad = profile.clone();
        bad.pool_address =
            "-1:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe".into();
        assert!(bad.validate().is_err(), "a masterchain pool");
        let mut bad = profile.clone();
        bad.pool_code_hash = "abcd".into();
        assert!(bad.validate().is_err(), "a short code hash");
        let mut bad = profile;
        bad.global_id = 9;
        assert!(bad.validate().is_err(), "an unknown network");
    }
}
