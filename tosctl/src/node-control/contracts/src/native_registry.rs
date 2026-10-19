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
//! [`build_policy`] refuses, before anything is signed or sent, every policy
//! the contract's admission check would refuse for its shape: a policy is
//! stored only after the contract has walked it and checked a signature from
//! every controller, so a policy that cannot be admitted would only burn the
//! relayer's gas. The contract remains the authority; this is an early,
//! explanatory refusal of the same rules.

use anyhow::{Result, bail};
use chain_block::{BuilderData, Cell, IBitstring};

/// The widest policy the registry admits.
///
/// Every operation that walks a policy -- registration, a policy update from
/// one maximum-width policy to another, recovery initiation and completion,
/// and capability authorization -- has been measured at this width and stays
/// at or below [`NATIVE_REGISTRY_GAS_CEILING`]. The contract refuses a wider
/// policy wherever one enters storage (exit
/// [`NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE`]).
pub const NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS: usize = 20;

/// Compute gas one masterchain transaction may use (ConfigParam 20). The
/// basechain limit is higher, so the masterchain limit is the binding one.
pub const NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT: u64 = 1_000_000;

/// The gas every policy-walking path must stay within at the maximum width:
/// 80% of [`NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT`], leaving 20% for opcode
/// repricing and contract changes before a supported policy stops fitting.
pub const NATIVE_REGISTRY_GAS_CEILING: u64 = NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT / 5 * 4;

/// Exit code of a policy wider than [`NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS`].
pub const NATIVE_REGISTRY_ERR_POLICY_TOO_WIDE: i32 = 2215;

/// Largest weight one controller may carry.
pub const NATIVE_REGISTRY_MAX_CONTROLLER_WEIGHT: u32 = 1_000_000;

/// Longest recovery timelock, in seconds.
pub const NATIVE_REGISTRY_MAX_RECOVERY_TIMELOCK: u64 = 31_536_000;

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

/// One controller key of a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePolicyController {
    pub public_key: [u8; 32],
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

/// Encodings of the Ed25519 8-torsion points, and the sign-bit aliases of the
/// two with x = 0, as stored: prohibited weak and non-canonical keys. For some
/// a signature can be forged with no secret; the VM itself refuses the
/// all-zero key and the canonical identity. The contract's `weak_ed25519_key?`
/// refuses the same set.
const FORGEABLE_ED25519_KEYS: [&str; 10] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];

/// Whether the contract refuses `key` as a controller: one of
/// [`FORGEABLE_ED25519_KEYS`], or an encoding whose y is at least 2^255 - 19
/// (a second spelling of a point). Mirrors the contract exactly, so a key it
/// admits is never refused here and the reverse.
fn is_forgeable_ed25519_key(key: &[u8; 32]) -> bool {
    let y_not_reduced =
        key[0] >= 0xed && key[1..31].iter().all(|&b| b == 0xff) && key[31] & 0x7f == 0x7f;
    y_not_reduced || FORGEABLE_ED25519_KEYS.contains(&hex::encode(key).as_str())
}

/// Serializes `policy` in the registry's canonical form: controllers sorted by
/// key, each linked to the next.
///
/// Errors for a policy the contract would refuse for its shape: no
/// controllers, more than [`NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS`], a zero
/// or duplicate key, a key anyone can sign for (an Ed25519 8-torsion encoding
/// or a non-canonical y, see [`is_forgeable_ed25519_key`]), a weight of zero
/// or above the maximum, an empty or unknown purpose set, a zero threshold, a
/// timelock above the maximum, or a threshold the controllers holding its
/// purpose cannot reach.
pub fn build_policy(policy: &NativePolicy) -> Result<Cell> {
    let count = policy.controllers.len();
    if count == 0 {
        bail!("a Native Registry policy needs at least one controller");
    }
    if count > NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS {
        bail!(
            "a Native Registry policy supports at most {NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS} \
             controllers, not {count}: every controller must sign the registration, and wider \
             policies do not fit one transaction's gas with headroom"
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

    let mut sorted = policy.controllers.clone();
    sorted.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    let mut totals = [0u64; 4];
    for (index, controller) in sorted.iter().enumerate() {
        if controller.public_key == [0u8; 32] {
            bail!("a Native Registry controller key must be nonzero");
        }
        if is_forgeable_ed25519_key(&controller.public_key) {
            bail!(
                "Native Registry controller key {} is one anyone can sign for",
                hex::encode(controller.public_key)
            );
        }
        if index > 0 && sorted[index - 1].public_key == controller.public_key {
            bail!(
                "duplicate Native Registry controller key {}",
                hex::encode(controller.public_key)
            );
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
                    .ok_or_else(|| anyhow::anyhow!("controller weight total overflows"))?;
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
    for controller in sorted.iter().rev() {
        let mut cell = BuilderData::new();
        cell.append_raw(&controller.public_key, 256)?
            .append_raw(&controller.public_key, 256)?
            .append_u32(controller.weight)?
            .append_u16(controller.purposes)?
            .append_bit_bool(controller.purposes & PURPOSE_RECOVERY != 0)?;
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
    Ok(root.into_cell()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controllers(count: usize) -> Vec<NativePolicyController> {
        (0..count)
            .map(|i| {
                let mut public_key = [0u8; 32];
                public_key[0] = 0x10;
                public_key[31] = u8::try_from(i + 1).unwrap_or(u8::MAX);
                NativePolicyController { public_key, weight: 1, purposes: PURPOSE_KNOWN_MASK }
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
        assert!(error.contains("at most"), "unexpected error: {error}");
    }

    #[test]
    fn shape_errors_are_refused() {
        assert!(build_policy(&policy(0)).is_err());
        let mut duplicate = policy(2);
        duplicate.controllers[1].public_key = duplicate.controllers[0].public_key;
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

    #[test]
    fn keys_anyone_can_sign_for_are_refused_like_the_contract_refuses_them() {
        let mut refused: Vec<[u8; 32]> = FORGEABLE_ED25519_KEYS
            .iter()
            .filter_map(|text| hex::decode(text).ok()?.try_into().ok())
            .collect();
        assert_eq!(refused.len(), FORGEABLE_ED25519_KEYS.len());
        // y = 2^255 - 19 and y = 2^255 - 1, each with and without the sign bit.
        for (first, last) in [(0xed, 0x7f), (0xed, 0xff), (0xff, 0x7f), (0xff, 0xff)] {
            let mut key = [0xffu8; 32];
            key[0] = first;
            key[31] = last;
            refused.push(key);
        }
        for key in refused {
            let mut weak = policy(2);
            weak.controllers[1].public_key = key;
            let refused_here = build_policy(&weak).is_err();
            assert!(refused_here, "{} was admitted", hex::encode(key));
        }
        // ec ff..ff 7f is the order-2 point and is refused. Lowering its top
        // byte to 0x7e gives y = 2^255 - 2^248 - 20 with the sign bit clear: a
        // reduced encoding outside the forgeable set, which the contract admits.
        let mut ordinary = policy(2);
        let mut key = [0xffu8; 32];
        key[0] = 0xec;
        key[31] = 0x7e;
        ordinary.controllers[1].public_key = key;
        assert!(build_policy(&ordinary).is_ok());
    }
}
