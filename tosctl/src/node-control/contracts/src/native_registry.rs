/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Controller policies for the TOS Native Service Registry
//! (`crypto/smartcont/native-registry-code.fc`).
//!
//! A controller is an ML-DSA-44 public key. The registry identifies it by its
//! key id, SHA-256 over `TOS-PQ-CONSENSUS-KEY-v1`, the suite number 1 as two
//! little-endian bytes and the 1,312 key bytes, and stores the key itself as
//! `len:uint32 ^chain`, a chain of full 127-byte cells ending in a non-empty
//! one.
//!
//! [`build_policy`] refuses, before anything is signed or sent, every policy
//! the contract's admission check would refuse for its shape: a policy is
//! stored only after the contract has walked it and checked a signature from
//! every controller, so a policy that cannot be admitted would only burn the
//! relayer's gas. The contract remains the authority; this is an early,
//! explanatory refusal of the same rules.

use anyhow::{Result, anyhow, bail};
use chain_block::{BuilderData, Cell, IBitstring};
use sha2::{Digest, Sha256};

/// The widest policy the registry admits.
///
/// Every operation that walks a policy -- registration, a policy update from
/// one maximum-width policy to another, recovery initiation and completion,
/// and capability authorization -- has been measured at this width and stays
/// at or below [`NATIVE_REGISTRY_GAS_CEILING`]; a disjoint update or recovery
/// initiation carrying two maximum-width signature sets also fits one relayed
/// external message. The contract refuses a wider policy wherever one enters
/// storage (exit [`NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE`]).
pub const NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS: usize = 8;

/// Compute gas one basechain transaction may use (genesis ConfigParam 21).
/// The registry runs in workchain 0 only.
pub const NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT: u64 = 2_000_000;

/// The gas every policy-walking path must stay within at the maximum width.
/// Fixed, rather than a share of [`NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT`], so
/// that a raised network limit cannot quietly widen what the registry admits.
pub const NATIVE_REGISTRY_GAS_CEILING: u64 = 800_000;

/// Exit code of a policy wider than [`NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS`].
pub const NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE: i32 = 2215;

/// Largest weight one controller may carry.
pub const NATIVE_REGISTRY_MAX_CONTROLLER_WEIGHT: u32 = 1_000_000;

/// Longest recovery timelock, in seconds.
pub const NATIVE_REGISTRY_MAX_RECOVERY_TIMELOCK: u64 = 31_536_000;

/// Length of an ML-DSA-44 public key, the one admitted controller suite.
pub const NATIVE_REGISTRY_PUBLIC_KEY_BYTES: usize = 1312;

/// Length of an ML-DSA-44 signature.
pub const NATIVE_REGISTRY_SIGNATURE_BYTES: usize = 2420;

/// The ML-DSA-44 context every registry signature is made under.
pub const NATIVE_REGISTRY_SIGNATURE_CONTEXT: &[u8] = b"TOS-NATIVE-REGISTRY";

/// Purpose bit: agent control (register, update policy, revoke).
pub const PURPOSE_AGENT_CONTROL: u16 = 1;
/// Purpose bit: delegation.
pub const PURPOSE_DELEGATION: u16 = 2;
/// Purpose bit: recovery.
pub const PURPOSE_RECOVERY: u16 = 4;
/// Purpose bit: capability control.
pub const PURPOSE_CAPABILITY_CONTROL: u16 = 8;
const PURPOSE_KNOWN_MASK: u16 = 15;
const MAGIC_POLICY: u32 = 0x4e56_5031;
const POLICY_SCHEMA: u16 = 1;
const KEY_ID_DOMAIN: &[u8] = b"TOS-PQ-CONSENSUS-KEY-v1";
const ML_DSA_44_SUITE: u16 = 1;
const CHAIN_CHUNK_BYTES: usize = 127;

/// One controller key of a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePolicyController {
    /// The ML-DSA-44 public key, [`NATIVE_REGISTRY_PUBLIC_KEY_BYTES`] long.
    pub public_key: Vec<u8>,
    pub weight: u32,
    /// Bitwise OR of the `PURPOSE_*` constants.
    pub purposes: u16,
}

/// An agent's controller policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePolicy {
    pub threshold: u32,
    pub recovery_threshold: u32,
    pub recovery_timelock: u64,
    pub controllers: Vec<NativePolicyController>,
}

/// The registry's identity for an ML-DSA-44 controller key.
///
/// Errors for a key that is not exactly [`NATIVE_REGISTRY_PUBLIC_KEY_BYTES`]
/// long.
pub fn controller_key_id(public_key: &[u8]) -> Result<[u8; 32]> {
    if public_key.len() != NATIVE_REGISTRY_PUBLIC_KEY_BYTES {
        bail!(
            "a Native Registry controller key is an ML-DSA-44 public key of \
             {NATIVE_REGISTRY_PUBLIC_KEY_BYTES} bytes, not {}",
            public_key.len()
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(ML_DSA_44_SUITE.to_le_bytes());
    hasher.update(public_key);
    Ok(hasher.finalize().into())
}

/// `bytes` as the registry stores key and signature material:
/// `len:uint32 ^chain`, the chain made of full 127-byte cells and a non-empty
/// last cell.
///
/// Errors for empty material or a length that does not fit 32 bits.
pub fn stored_bytes(bytes: &[u8]) -> Result<Cell> {
    if bytes.is_empty() {
        bail!("stored key or signature material must not be empty");
    }
    let length = u32::try_from(bytes.len())?;
    let mut next: Option<Cell> = None;
    for chunk in bytes.chunks(CHAIN_CHUNK_BYTES).rev() {
        let mut cell = BuilderData::new();
        cell.append_raw(chunk, chunk.len().checked_mul(8).ok_or_else(|| anyhow!("overflow"))?)?;
        if let Some(link) = next {
            cell.checked_append_reference(link)?;
        }
        next = Some(cell.into_cell()?);
    }
    let Some(chain) = next else {
        bail!("stored key or signature material must not be empty");
    };
    let mut wrapper = BuilderData::new();
    wrapper.append_u32(length)?.checked_append_reference(chain)?;
    wrapper.into_cell()
}

/// Serializes `policy` in the registry's canonical form: controllers sorted by
/// key id, each `key_id weight purposes recovery ^stored_key`, linked to the
/// next.
///
/// Errors for a policy the contract would refuse for its shape: no
/// controllers, more than [`NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS`], a key
/// that is not an ML-DSA-44 public key's length, a duplicate key, a weight of
/// zero or above the maximum, an empty or unknown purpose set, a zero
/// threshold, a timelock above the maximum, or a threshold the controllers
/// holding its purpose cannot reach.
pub fn build_policy(policy: &NativePolicy) -> Result<Cell> {
    let count = policy.controllers.len();
    if count == 0 {
        bail!("a Native Registry policy needs at least one controller");
    }
    if count > NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS {
        bail!(
            "a Native Registry policy supports at most {NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS} \
             controllers, not {count}: every controller must sign the registration, and wider \
             policies do not fit one transaction's gas and one message with headroom"
        );
    }
    if policy.threshold == 0 || policy.recovery_threshold == 0 {
        bail!("Native Registry policy thresholds must be positive");
    }
    if policy.recovery_timelock > NATIVE_REGISTRY_MAX_RECOVERY_TIMELOCK {
        bail!(
            "recovery timelock {} exceeds the maximum of {NATIVE_REGISTRY_MAX_RECOVERY_TIMELOCK} s",
            policy.recovery_timelock
        );
    }

    let mut sorted = Vec::with_capacity(count);
    for controller in &policy.controllers {
        sorted.push((controller_key_id(&controller.public_key)?, controller));
    }
    sorted.sort_by_key(|entry| entry.0);
    let mut totals = [0u64; 4];
    for (index, (key_id, controller)) in sorted.iter().enumerate() {
        if index > 0 && sorted[index - 1].0 == *key_id {
            bail!("duplicate Native Registry controller key {}", hex::encode(key_id));
        }
        if controller.weight == 0 || controller.weight > NATIVE_REGISTRY_MAX_CONTROLLER_WEIGHT {
            bail!(
                "controller weight {} is outside 1..={NATIVE_REGISTRY_MAX_CONTROLLER_WEIGHT}",
                controller.weight
            );
        }
        if controller.purposes == 0 || controller.purposes & !PURPOSE_KNOWN_MASK != 0 {
            bail!("controller purposes {:#x} are empty or unknown", controller.purposes);
        }
        for (bit, total) in totals.iter_mut().enumerate() {
            if controller.purposes & (1 << bit) != 0 {
                *total = total
                    .checked_add(u64::from(controller.weight))
                    .ok_or_else(|| anyhow!("controller weight total overflows"))?;
            }
        }
    }
    let [agent, delegation, recovery, capability] = totals;
    let threshold = u64::from(policy.threshold);
    if threshold > agent || threshold > delegation || threshold > capability {
        bail!(
            "threshold {threshold} is unreachable: agent-control weight {agent}, delegation \
             weight {delegation}, capability-control weight {capability}"
        );
    }
    if u64::from(policy.recovery_threshold) > recovery {
        bail!(
            "recovery threshold {} is unreachable: recovery weight {recovery}",
            policy.recovery_threshold
        );
    }

    let mut next: Option<Cell> = None;
    for (key_id, controller) in sorted.iter().rev() {
        let mut cell = BuilderData::new();
        cell.append_raw(key_id, 256)?
            .append_u32(controller.weight)?
            .append_u16(controller.purposes)?
            .append_bit_bool(controller.purposes & PURPOSE_RECOVERY != 0)?
            .checked_append_reference(stored_bytes(&controller.public_key)?)?;
        if let Some(link) = next {
            cell.checked_append_reference(link)?;
        }
        next = Some(cell.into_cell()?);
    }
    let Some(first) = next else {
        bail!("a Native Registry policy needs at least one controller");
    };
    let count = u8::try_from(count)?;
    let mut root = BuilderData::new();
    root.append_u32(MAGIC_POLICY)?
        .append_u16(POLICY_SCHEMA)?
        .append_u32(policy.threshold)?
        .append_u32(policy.recovery_threshold)?
        .append_u64(policy.recovery_timelock)?
        .append_u8(count)?
        .checked_append_reference(first)?;
    root.into_cell()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: usize) -> Vec<u8> {
        let mut public_key = vec![0x10u8; NATIVE_REGISTRY_PUBLIC_KEY_BYTES];
        public_key[0] = u8::try_from(tag).unwrap_or(u8::MAX);
        public_key
    }

    fn controllers(count: usize) -> Vec<NativePolicyController> {
        (0..count)
            .map(|i| NativePolicyController {
                public_key: key(i + 1),
                weight: 1,
                purposes: PURPOSE_KNOWN_MASK,
            })
            .collect()
    }

    fn policy(count: usize) -> NativePolicy {
        let threshold = u32::try_from(count).unwrap_or(u32::MAX).max(1);
        NativePolicy {
            threshold,
            recovery_threshold: threshold,
            recovery_timelock: 10,
            controllers: controllers(count),
        }
    }

    #[test]
    fn maximum_width_builds_and_one_more_is_refused() {
        assert!(build_policy(&policy(NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS)).is_ok());
        let error = build_policy(&policy(NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS + 1))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains("at most 8"), "unexpected error: {error}");
    }

    #[test]
    fn shape_errors_are_refused() {
        assert!(build_policy(&policy(0)).is_err());
        let mut duplicate = policy(2);
        duplicate.controllers[1].public_key = duplicate.controllers[0].public_key.clone();
        assert!(build_policy(&duplicate).is_err());
        let mut heavy = policy(1);
        heavy.controllers[0].weight = NATIVE_REGISTRY_MAX_CONTROLLER_WEIGHT + 1;
        assert!(build_policy(&heavy).is_err());
        let mut unknown = policy(1);
        unknown.controllers[0].purposes = 0x10;
        assert!(build_policy(&unknown).is_err());
        let mut unreachable = policy(2);
        unreachable.threshold = 3;
        assert!(build_policy(&unreachable).is_err());
        let mut long = policy(1);
        long.recovery_timelock = NATIVE_REGISTRY_MAX_RECOVERY_TIMELOCK + 1;
        assert!(build_policy(&long).is_err());
    }

    /// An Ed25519-sized key, an empty key and a key one byte short or long
    /// are refused: the registry admits one suite, ML-DSA-44.
    #[test]
    fn keys_of_any_other_length_are_refused() {
        for length in
            [0, 32, NATIVE_REGISTRY_PUBLIC_KEY_BYTES - 1, NATIVE_REGISTRY_PUBLIC_KEY_BYTES + 1]
        {
            let mut wrong = policy(1);
            wrong.controllers[0].public_key = vec![0x10; length];
            let error = build_policy(&wrong).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(error.contains("ML-DSA-44"), "length {length}: {error}");
        }
    }

    /// The key id is SHA-256 over the domain, the suite number 1 as the bytes
    /// 01 00, and the key, independent of how the hash is fed.
    #[test]
    fn key_id_binds_domain_little_endian_suite_and_key() {
        let public_key = key(7);
        let mut preimage = b"TOS-PQ-CONSENSUS-KEY-v1".to_vec();
        preimage.extend_from_slice(&[0x01, 0x00]);
        preimage.extend_from_slice(&public_key);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(controller_key_id(&public_key).ok(), Some(expected));
    }

    /// Controllers are emitted in key-id order whatever order they are given
    /// in, and each carries its key as a 1,312-byte stored wrapper.
    #[test]
    fn controllers_are_ordered_by_key_id_and_carry_the_stored_key() -> Result<()> {
        let mut reversed = policy(3);
        reversed.controllers.reverse();
        let built = build_policy(&reversed)?;
        assert_eq!(built.repr_hash(), build_policy(&policy(3))?.repr_hash());

        let mut root = chain_block::SliceData::load_cell(built)?;
        root.move_by(32 + 16 + 32 + 32 + 64)?;
        assert_eq!(root.get_next_int(8)?, 3);
        let mut cursor = Some(root.checked_drain_reference()?);
        let mut previous: Option<Vec<u8>> = None;
        while let Some(cell) = cursor {
            let mut controller = chain_block::SliceData::load_cell(cell)?;
            let id = controller.get_next_bytes(32)?;
            controller.move_by(32 + 16 + 1)?;
            let mut stored =
                chain_block::SliceData::load_cell(controller.checked_drain_reference()?)?;
            assert_eq!(stored.get_next_u32()?, 1312);
            if let Some(previous) = &previous {
                assert!(previous < &id, "controllers out of key-id order");
            }
            previous = Some(id);
            cursor = if controller.remaining_references() > 0 {
                Some(controller.checked_drain_reference()?)
            } else {
                None
            };
        }
        Ok(())
    }
}
