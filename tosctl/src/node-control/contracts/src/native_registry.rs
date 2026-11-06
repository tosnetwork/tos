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

/// Explicit chain and reviewed runtime identities supplied by the operator.
/// This value is configuration, not proof of the current chain or authorization.
#[derive(Clone, Debug)]
pub struct NativeRegistryDomain {
    pub genesis_root: [u8; 32],
    pub genesis_file: [u8; 32],
    pub network_tag: [u8; 32],
    pub runtime_code_hash: [u8; 32],
}

/// Unsigned operation fields. Payload semantics and controller authority remain
/// the contract's responsibility; this builder neither signs nor submits.
#[derive(Clone, Debug)]
pub struct NativeRegistryAction {
    pub kind: u8,
    pub generation: u64,
    pub sequence: u64,
    pub object_id: [u8; 32],
    pub predecessor: [u8; 32],
    pub nonce: [u8; 32],
    pub payload: Cell,
}

/// Encode the canonical action header with an explicit configured domain.
/// Kinds1..6 target Agents; kinds7..10 target Capabilities.
pub fn build_native_action(
    domain: &NativeRegistryDomain,
    action: &NativeRegistryAction,
) -> Result<Cell> {
    use anyhow::ensure;
    ensure!((1..=10).contains(&action.kind), "unknown native registry action kind");
    ensure!(
        action.generation > 0 && action.sequence > 0,
        "zero native registry generation or sequence"
    );
    ensure!(action.nonce != [0; 32], "zero native registry action nonce");
    ensure!(action.object_id != [0; 32], "zero native registry object identity");
    validate_native_domain(domain)?;
    let mut code = BuilderData::new();
    code.append_raw(&domain.runtime_code_hash, 256)?;
    let mut chain = BuilderData::new();
    chain
        .append_raw(&domain.genesis_root, 256)?
        .append_raw(&domain.genesis_file, 256)?
        .append_raw(&domain.network_tag, 256)?;
    chain.checked_append_reference(code.into_cell()?)?;
    let mut out = BuilderData::new();
    out.append_u32(0x4e56_4131)?
        .append_u16(1)?
        .append_u8(action.kind)?
        .append_u8(if action.kind <= 6 { 1 } else { 2 })?
        .append_u64(action.generation)?
        .append_u64(action.sequence)?
        .append_raw(&action.object_id, 256)?
        .append_raw(&action.predecessor, 256)?
        .append_raw(&action.nonce, 256)?;
    out.checked_append_reference(chain.into_cell()?)?;
    out.checked_append_reference(action.payload.clone())?;
    Ok(out.into_cell()?)
}

/// Check exact action shape and configured domain before requesting a signature.
/// A matching header does not establish signature authority or business validity.
pub fn check_native_action_domain(action: &Cell, domain: &NativeRegistryDomain) -> Result<()> {
    use anyhow::{Context, ensure};
    use chain_block::{CellType, SliceData};
    ensure!(
        action.cell_type() == CellType::Ordinary && action.level() == 0,
        "ordinary native registry action required"
    );
    let mut s = SliceData::load_cell(action.clone())?;
    ensure!(
        s.get_next_u32()? == 0x4e56_4131 && s.get_next_u16()? == 1,
        "native registry action tag or schema"
    );
    let kind = s.get_next_byte()?;
    let target = s.get_next_byte()?;
    ensure!(
        (1..=10).contains(&kind) && target == if kind <= 6 { 1 } else { 2 },
        "native registry target kind mismatch"
    );
    let generation = s.get_next_u64()?;
    let sequence = s.get_next_u64()?;
    let object_id = s.get_next_bytes(32)?.try_into().ok().context("object id width")?;
    let predecessor = s.get_next_bytes(32)?.try_into().ok().context("predecessor width")?;
    let nonce = s.get_next_bytes(32)?.try_into().ok().context("nonce width")?;
    s.checked_drain_reference()?;
    let payload = s.checked_drain_reference()?;
    ensure!(
        s.remaining_bits() == 0 && s.remaining_references() == 0,
        "native registry action trailing data"
    );
    let expected = build_native_action(
        domain,
        &NativeRegistryAction {
            kind,
            generation,
            sequence,
            object_id,
            predecessor,
            nonce,
            payload,
        },
    )?;
    ensure!(
        action.repr_hash() == expected.repr_hash(),
        "native registry configured domain mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    fn fixture() -> (NativeRegistryDomain, NativeRegistryAction) {
        (
            NativeRegistryDomain {
                genesis_root: [1; 32],
                genesis_file: [2; 32],
                network_tag: [3; 32],
                runtime_code_hash: [4; 32],
            },
            NativeRegistryAction {
                kind: 1,
                generation: 1,
                sequence: 1,
                object_id: [5; 32],
                predecessor: [0; 32],
                nonce: [6; 32],
                payload: Cell::default(),
            },
        )
    }
    #[test]
    fn configured_domain_is_required_before_signing() -> Result<()> {
        let (domain, action) = fixture();
        let cell = build_native_action(&domain, &action)?;
        check_native_action_domain(&cell, &domain)?;
        for field in 0..4 {
            let mut wrong = domain.clone();
            match field {
                0 => wrong.genesis_root[0] ^= 1,
                1 => wrong.genesis_file[0] ^= 1,
                2 => wrong.network_tag[0] ^= 1,
                _ => wrong.runtime_code_hash[0] ^= 1,
            }
            let err =
                check_native_action_domain(&cell, &wrong).expect_err("changed domain must refuse");
            assert!(err.to_string().contains("configured domain mismatch"));
        }
        Ok(())
    }
    #[test]
    fn unsigned_action_shape_refuses_invalid_fields() -> Result<()> {
        let (domain, action) = fixture();
        for kind in [0, 11, 255] {
            let mut a = action.clone();
            a.kind = kind;
            assert!(
                build_native_action(&domain, &a)
                    .expect_err("kind")
                    .to_string()
                    .contains("unknown native registry action kind")
            );
        }
        let mut a = action.clone();
        a.nonce = [0; 32];
        assert!(
            build_native_action(&domain, &a)
                .expect_err("nonce")
                .to_string()
                .contains("zero native registry action nonce")
        );
        let mut a = action.clone();
        a.generation = 0;
        assert!(
            build_native_action(&domain, &a)
                .expect_err("generation")
                .to_string()
                .contains("zero native registry generation or sequence")
        );
        for field in 0..4 {
            let mut zero = domain.clone();
            match field {
                0 => zero.genesis_root = [0; 32],
                1 => zero.genesis_file = [0; 32],
                2 => zero.network_tag = [0; 32],
                _ => zero.runtime_code_hash = [0; 32],
            }
            assert!(
                build_native_action(&zero, &action)
                    .expect_err("zero domain")
                    .to_string()
                    .contains("zero native registry domain identity")
            );
        }
        let mut a = action;
        a.sequence = 0;
        assert!(
            build_native_action(&domain, &a)
                .expect_err("sequence")
                .to_string()
                .contains("zero native registry generation or sequence")
        );
        Ok(())
    }
}

fn validate_native_domain(domain: &NativeRegistryDomain) -> Result<()> {
    for value in
        [&domain.genesis_root, &domain.genesis_file, &domain.network_tag, &domain.runtime_code_hash]
    {
        anyhow::ensure!(*value != [0; 32], "zero native registry domain identity");
    }
    Ok(())
}

/// Deterministic initial object data and address. The explicit network label
/// uses a single cell (1..127 bytes); the configured tag is its SHA-256 digest.
/// This only constructs deployment data; it proves no authority or chain state.
pub fn build_native_registry_deployment(
    domain: &NativeRegistryDomain,
    object_kind: u8,
    object_id: [u8; 32],
    workchain: i8,
    network_label: &[u8],
    runtime_code: &Cell,
) -> Result<(chain_block::StateInit, chain_block::MsgAddressInt)> {
    use anyhow::ensure;
    use chain_block::Serializable;
    use sha2::{Digest, Sha256};
    validate_native_domain(domain)?;
    ensure!(matches!(object_kind, 1 | 2), "native registry object kind");
    ensure!(object_id != [0; 32], "zero native registry object identity");
    ensure!((1..=127).contains(&network_label.len()), "native registry network label length");
    let tag: [u8; 32] = Sha256::digest(network_label).into();
    ensure!(tag == domain.network_tag, "native registry network label mismatch");
    ensure!(
        runtime_code.repr_hash().as_array() == &domain.runtime_code_hash,
        "native registry runtime code mismatch"
    );
    let mut label = BuilderData::new();
    label.append_raw(network_label, network_label.len() * 8)?;
    let mut runtime = BuilderData::new();
    runtime.append_i32(i32::from(workchain))?.append_raw(&domain.runtime_code_hash, 256)?;
    runtime.checked_append_reference(label.into_cell()?)?;
    runtime.checked_append_reference(runtime_code.clone())?;
    let mut config = BuilderData::new();
    config
        .append_raw(&domain.genesis_root, 256)?
        .append_raw(&domain.genesis_file, 256)?
        .append_raw(&domain.network_tag, 256)?;
    config.checked_append_reference(runtime.into_cell()?)?;
    let mut data = BuilderData::new();
    data.append_u32(0x4e56_4431)?
        .append_u16(1)?
        .append_u8(object_kind)?
        .append_raw(&object_id, 256)?;
    data.checked_append_reference(config.into_cell()?)?;
    data.append_bit_zero()?;
    let init = chain_block::StateInit::with_code_and_data(runtime_code.clone(), data.into_cell()?);
    let root = init.write_to_new_cell()?.into_cell()?;
    let address = chain_block::MsgAddressInt::with_params(i32::from(workchain), root.repr_hash())?;
    Ok((init, address))
}

#[cfg(test)]
mod deployment_tests {
    use super::*;
    use chain_block::Serializable;
    use sha2::{Digest, Sha256};
    fn fixture() -> (NativeRegistryDomain, Cell) {
        let code = Cell::default();
        (
            NativeRegistryDomain {
                genesis_root: [1; 32],
                genesis_file: [2; 32],
                network_tag: Sha256::digest(b"fixture-network").into(),
                runtime_code_hash: *code.repr_hash().as_array(),
            },
            code,
        )
    }
    #[test]
    fn deployment_address_binds_runtime_workchain_and_domain() -> Result<()> {
        let (d, code) = fixture();
        let (init, address) =
            build_native_registry_deployment(&d, 1, [3; 32], 0, b"fixture-network", &code)?;
        assert_eq!(
            address.address().storage(),
            init.write_to_new_cell()?.into_cell()?.repr_hash().as_slice()
        );
        let (_, other) =
            build_native_registry_deployment(&d, 1, [3; 32], -1, b"fixture-network", &code)?;
        assert_ne!(address, other);
        assert_ne!(address.address(), other.address());
        let mut changed = d.clone();
        changed.genesis_file[0] ^= 1;
        let (_, other) =
            build_native_registry_deployment(&changed, 1, [3; 32], 0, b"fixture-network", &code)?;
        assert_ne!(address, other);
        Ok(())
    }
    #[test]
    fn deployment_refuses_mismatched_code_label_or_object() -> Result<()> {
        let (d, code) = fixture();
        let error = |domain: &NativeRegistryDomain, kind, id, label: &[u8]| {
            build_native_registry_deployment(domain, kind, id, 0, label, &code)
                .expect_err("must refuse")
                .to_string()
        };
        assert!(error(&d, 0, [3; 32], b"fixture-network").contains("object kind"));
        assert!(
            error(&d, 1, [0; 32], b"fixture-network")
                .contains("zero native registry object identity")
        );
        let mut empty = d.clone();
        empty.network_tag = Sha256::digest(b"").into();
        assert!(error(&empty, 1, [3; 32], b"").contains("network label length"));
        let mut long = d.clone();
        long.network_tag = Sha256::digest([7; 128]).into();
        assert!(error(&long, 1, [3; 32], &[7; 128]).contains("network label length"));
        let mut zero = d.clone();
        zero.genesis_root = [0; 32];
        assert!(
            error(&zero, 1, [3; 32], b"fixture-network")
                .contains("zero native registry domain identity")
        );
        assert!(error(&d, 1, [3; 32], b"wrong-network").contains("network label mismatch"));
        let mut wrong = d;
        wrong.runtime_code_hash = [9; 32];
        assert!(error(&wrong, 1, [3; 32], b"fixture-network").contains("runtime code mismatch"));
        Ok(())
    }
}

/// Deterministic object identity and unsigned registration payload, not a
/// signature or authorization. Runtime code binds the address, not this ID.
pub struct NativeRegistryRegistration {
    pub object_id: [u8; 32],
    pub payload: Cell,
}

fn native_identity_domain(domain: &NativeRegistryDomain) -> Result<Cell> {
    validate_native_domain(domain)?;
    let mut b = BuilderData::new();
    b.append_raw(&domain.genesis_root, 256)?
        .append_raw(&domain.genesis_file, 256)?
        .append_raw(&domain.network_tag, 256)?;
    Ok(b.into_cell()?)
}

/// Use the existing admission-checked policy builder before deriving an Agent ID.
pub fn build_native_agent_registration(
    domain: &NativeRegistryDomain,
    object_nonce: [u8; 32],
    policy: &NativePolicy,
) -> Result<NativeRegistryRegistration> {
    anyhow::ensure!(object_nonce != [0; 32], "zero native registry object nonce");
    let policy = build_policy(policy)?;
    let mut identity = BuilderData::new();
    identity
        .append_u32(0x4e56_4931)?
        .append_u8(1)?
        .append_raw(&object_nonce, 256)?
        .append_raw(policy.repr_hash().as_slice(), 256)?;
    identity.checked_append_reference(native_identity_domain(domain)?)?;
    let object_id = *identity.into_cell()?.repr_hash().as_array();
    let mut payload = BuilderData::new();
    payload.append_raw(&object_nonce, 256)?.checked_append_reference(policy)?;
    Ok(NativeRegistryRegistration { object_id, payload: payload.into_cell()? })
}

/// Canonical protocol version text is printable non-space ASCII,1..128bytes,
/// stored in a minimal byte-aligned snake, matching contract admission.
pub fn build_native_capability_registration(
    domain: &NativeRegistryDomain,
    object_nonce: [u8; 32],
    owner_agent: [u8; 32],
    version: &[u8],
    manifest_digest: [u8; 32],
) -> Result<NativeRegistryRegistration> {
    use anyhow::ensure;
    ensure!(object_nonce != [0; 32], "zero native registry object nonce");
    ensure!(owner_agent != [0; 32], "zero native registry capability owner");
    ensure!(manifest_digest != [0; 32], "zero native registry manifest digest");
    let (version_hash, name) = native_protocol_text(version)?;
    let mut details = BuilderData::new();
    details.append_raw(&version_hash, 256)?.append_raw(&manifest_digest, 256)?;
    let details_cell = details.clone().into_cell()?;
    let mut identity = BuilderData::new();
    identity
        .append_u32(0x4e56_4931)?
        .append_u8(2)?
        .append_raw(&object_nonce, 256)?
        .append_raw(&owner_agent, 256)?;
    identity.checked_append_reference(native_identity_domain(domain)?)?;
    identity.checked_append_reference(details_cell)?;
    let object_id = *identity.into_cell()?.repr_hash().as_array();
    details.checked_append_reference(name)?;
    let mut payload = BuilderData::new();
    payload
        .append_raw(&object_nonce, 256)?
        .append_raw(&owner_agent, 256)?
        .checked_append_reference(details.into_cell()?)?;
    Ok(NativeRegistryRegistration { object_id, payload: payload.into_cell()? })
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    fn domain() -> NativeRegistryDomain {
        NativeRegistryDomain {
            genesis_root: [1; 32],
            genesis_file: [2; 32],
            network_tag: [3; 32],
            runtime_code_hash: [4; 32],
        }
    }
    fn policy() -> NativePolicy {
        NativePolicy {
            threshold: 1,
            recovery_threshold: 1,
            recovery_timelock: 10,
            controllers: vec![NativePolicyController {
                public_key: [9; 32],
                weight: 1,
                purposes: 15,
            }],
        }
    }
    #[test]
    fn agent_identity_binds_genesis_nonce_and_policy() -> Result<()> {
        let d = domain();
        let a = build_native_agent_registration(&d, [5; 32], &policy())?;
        let mut changed = d.clone();
        changed.genesis_file[0] ^= 1;
        assert_ne!(
            a.object_id,
            build_native_agent_registration(&changed, [5; 32], &policy())?.object_id
        );
        assert_ne!(a.object_id, build_native_agent_registration(&d, [6; 32], &policy())?.object_id);
        let mut p = policy();
        p.recovery_timelock = 11;
        assert_ne!(a.object_id, build_native_agent_registration(&d, [5; 32], &p)?.object_id);
        changed = d.clone();
        changed.runtime_code_hash[0] ^= 1;
        assert_eq!(
            a.object_id,
            build_native_agent_registration(&changed, [5; 32], &policy())?.object_id
        );
        assert!(
            build_native_agent_registration(&d, [0; 32], &policy())
                .err()
                .is_some_and(|e| e.to_string().contains("object nonce"))
        );
        let mut p = policy();
        p.controllers.clear();
        assert!(build_native_agent_registration(&d, [5; 32], &p).is_err());
        Ok(())
    }
    #[test]
    fn capability_refuses_invalid_identity_and_text() -> Result<()> {
        let d = domain();
        let e = |nonce, owner, version: &[u8], manifest| {
            build_native_capability_registration(&d, nonce, owner, version, manifest)
                .err()
                .expect("must refuse")
                .to_string()
        };
        assert!(e([0; 32], [6; 32], b"1.0.0", [7; 32]).contains("object nonce"));
        assert!(e([5; 32], [0; 32], b"1.0.0", [7; 32]).contains("capability owner"));
        assert!(e([5; 32], [6; 32], b"1.0.0", [0; 32]).contains("manifest digest"));
        for text in [&b""[..], &[b'a'; 129][..]] {
            assert!(e([5; 32], [6; 32], text, [7; 32]).contains("version length"));
        }
        for text in [&b" "[..], &b"a\0"[..], &[0x7f][..], &[0x80][..]] {
            assert!(e([5; 32], [6; 32], text, [7; 32]).contains("version characters"));
        }
        Ok(())
    }
    #[test]
    fn maximum_version_uses_minimal_two_cell_snake() -> Result<()> {
        use chain_block::SliceData;
        let d = domain();
        let registration =
            build_native_capability_registration(&d, [5; 32], [6; 32], &[b'a'; 128], [7; 32])?;
        let mut p = SliceData::load_cell(registration.payload)?;
        p.get_next_bytes(64)?;
        let mut details = SliceData::load_cell(p.checked_drain_reference()?)?;
        details.get_next_bytes(64)?;
        let mut name = SliceData::load_cell(details.checked_drain_reference()?)?;
        assert_eq!(name.remaining_bits(), 1016);
        assert_eq!(name.remaining_references(), 1);
        assert_eq!(name.get_next_bytes(127)?, vec![b'a'; 127]);
        let mut tail = SliceData::load_cell(name.checked_drain_reference()?)?;
        assert_eq!(tail.remaining_bits(), 8);
        assert_eq!(tail.remaining_references(), 0);
        assert_eq!(tail.get_next_byte()?, b'a');
        Ok(())
    }
}

/// Public controller signature bytes supplied by a separate custody owner.
/// Cryptographic validity does not establish membership in a current policy.
#[derive(Clone)]
pub struct NativeControllerSignature {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

pub(crate) fn native_signature_chain(
    action: &Cell,
    signatures: &[NativeControllerSignature],
    allow_empty: bool,
) -> Result<Cell> {
    use anyhow::{Context, ensure};
    ensure!(
        signatures.len() <= NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS
            && (allow_empty || !signatures.is_empty()),
        "native registry signature count"
    );
    let mut sorted = signatures.to_vec();
    sorted.sort_by_key(|s| s.public_key);
    for (i, s) in sorted.iter().enumerate() {
        ensure!(
            i == 0 || sorted[i - 1].public_key != s.public_key,
            "duplicate native registry signature"
        );
        let key = ed25519_dalek::VerifyingKey::from_bytes(&s.public_key)
            .context("native registry signature key")?;
        key.verify_strict(
            action.repr_hash().as_slice(),
            &ed25519_dalek::Signature::from_bytes(&s.signature),
        )
        .context("native registry signature verification failed")?;
    }
    let mut next = None;
    for s in sorted.iter().rev() {
        let mut b = BuilderData::new();
        b.append_raw(&s.public_key, 256)?.append_raw(&s.signature, 512)?;
        if let Some(cell) = next {
            b.checked_append_reference(cell)?;
        }
        next = Some(b.into_cell()?);
    }
    let mut root = BuilderData::new();
    root.append_u8(u8::try_from(sorted.len())?)?;
    if let Some(cell) = next {
        root.checked_append_reference(cell)?;
    }
    Ok(root.into_cell()?)
}

/// Build the caller-to-Agent envelope after exact domain and signature checks.
/// Capability actions route through their owning Agent; this function does not
/// infer that destination, current policy, threshold, consent or predecessor.
pub fn build_native_submission(
    domain: &NativeRegistryDomain,
    action: &Cell,
    query_id: u64,
    authority: &[NativeControllerSignature],
    counterparty: &[NativeControllerSignature],
) -> Result<Cell> {
    use chain_block::SliceData;
    check_native_action_domain(action, domain)?;
    let mut header = SliceData::load_cell(action.clone())?;
    header.get_next_u32()?;
    header.get_next_u16()?;
    let kind = header.get_next_byte()?;
    // Policy update and recovery initiation need possession of the policy they
    // install, a transfer needs the receiving owner's consent: the contract
    // refuses each of them without counterparty signatures, every other kind
    // with any.
    if native_kind_takes_counterparty(kind) {
        anyhow::ensure!(
            !counterparty.is_empty(),
            "native registry counterparty consent required for action kind {kind}"
        );
    } else {
        anyhow::ensure!(
            counterparty.is_empty(),
            "unexpected native registry counterparty signatures"
        );
    }
    let auth = native_signature_chain(action, authority, false)?;
    let counter = native_signature_chain(action, counterparty, true)?;
    let mut body = BuilderData::new();
    body.append_u32(if kind <= 6 { 0x4e56_0001 } else { 0x4e56_0002 })?.append_u64(query_id)?;
    body.checked_append_reference(action.clone())?;
    body.checked_append_reference(auth)?;
    body.checked_append_reference(counter)?;
    Ok(body.into_cell()?)
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use ed25519_dalek::Signer;
    fn fixture(kind: u8) -> Result<(NativeRegistryDomain, Cell)> {
        let d = NativeRegistryDomain {
            genesis_root: [1; 32],
            genesis_file: [2; 32],
            network_tag: [3; 32],
            runtime_code_hash: [4; 32],
        };
        let a = build_native_action(
            &d,
            &NativeRegistryAction {
                kind,
                generation: 1,
                sequence: 1,
                object_id: [5; 32],
                predecessor: [0; 32],
                nonce: [6; 32],
                payload: Cell::default(),
            },
        )?;
        Ok((d, a))
    }
    fn public_fixture_signature(action: &Cell, seed: u8) -> NativeControllerSignature {
        // Deliberately public deterministic test fixture, never an operational key.
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        NativeControllerSignature {
            public_key: key.verifying_key().to_bytes(),
            signature: key.sign(action.repr_hash().as_slice()).to_bytes(),
        }
    }
    #[test]
    fn submission_checks_signatures_and_canonical_order() -> Result<()> {
        use chain_block::SliceData;
        let (d, a) = fixture(1)?;
        let x = public_fixture_signature(&a, 71);
        let y = public_fixture_signature(&a, 72);
        let body = build_native_submission(&d, &a, 9, &[x.clone(), y.clone()], &[])?;
        assert_eq!(body, build_native_submission(&d, &a, 9, &[y, x], &[])?);
        let mut s = SliceData::load_cell(body)?;
        assert_eq!(s.get_next_u32()?, 0x4e560001);
        assert_eq!(s.get_next_u64()?, 9);
        Ok(())
    }
    #[test]
    fn signature_errors_and_width_stay_refused() -> Result<()> {
        let (d, a) = fixture(1)?;
        let x = public_fixture_signature(&a, 73);
        let mut bad = x.clone();
        bad.signature[3] ^= 1;
        assert!(
            build_native_submission(&d, &a, 1, &[bad], &[])
                .err()
                .is_some_and(|e| e.to_string().contains("signature verification failed"))
        );
        assert!(
            build_native_submission(&d, &a, 1, &[x.clone(), x], &[])
                .err()
                .is_some_and(|e| e.to_string().contains("duplicate"))
        );
        assert!(
            build_native_submission(&d, &a, 1, &[], &[])
                .err()
                .is_some_and(|e| e.to_string().contains("signature count"))
        );
        let too_many: Vec<_> = (1..=21).map(|s| public_fixture_signature(&a, s)).collect();
        assert!(
            build_native_submission(&d, &a, 1, &too_many, &[])
                .err()
                .is_some_and(|e| e.to_string().contains("signature count"))
        );
        Ok(())
    }
    #[test]
    fn counterparty_and_domain_are_separate_from_crypto() -> Result<()> {
        use chain_block::SliceData;
        let (d, a) = fixture(1)?;
        let x = public_fixture_signature(&a, 74);
        assert!(
            build_native_submission(&d, &a, 1, &[x.clone()], &[x.clone()])
                .err()
                .is_some_and(|e| e.to_string().contains("unexpected native registry counterparty"))
        );
        let mut wrong = d;
        wrong.genesis_root[0] ^= 1;
        assert!(
            build_native_submission(&wrong, &a, 1, &[x], &[])
                .err()
                .is_some_and(|e| e.to_string().contains("configured domain mismatch"))
        );
        let (d, a) = fixture(9)?;
        let x = public_fixture_signature(&a, 75);
        let body = build_native_submission(&d, &a, 1, &[x.clone()], &[x])?;
        let mut s = SliceData::load_cell(body)?;
        assert_eq!(s.get_next_u32()?, 0x4e560002);
        Ok(())
    }
}

/// Action kinds, as numbered by the contract.
pub const NATIVE_KIND_REGISTER_AGENT: u8 = 1;
pub const NATIVE_KIND_UPDATE_AGENT_POLICY: u8 = 2;
pub const NATIVE_KIND_DELEGATE_AGENT: u8 = 3;
pub const NATIVE_KIND_INITIATE_RECOVERY: u8 = 4;
pub const NATIVE_KIND_COMPLETE_RECOVERY: u8 = 5;
pub const NATIVE_KIND_REVOKE_AGENT: u8 = 6;
pub const NATIVE_KIND_REGISTER_CAPABILITY: u8 = 7;
pub const NATIVE_KIND_ADD_CAPABILITY_VERSION: u8 = 8;
pub const NATIVE_KIND_TRANSFER_CAPABILITY: u8 = 9;
pub const NATIVE_KIND_REVOKE_CAPABILITY: u8 = 10;

/// Most delegations one Agent may hold; the contract refuses the next one.
pub const NATIVE_REGISTRY_MAX_DELEGATIONS: u16 = 128;
/// Most versions one Capability may hold; the contract refuses the next one.
pub const NATIVE_REGISTRY_MAX_VERSIONS: u16 = 256;

const MAGIC_STATE: u32 = 0x4e56_5331;
const STATE_SCHEMA: u16 = 1;

/// Release BOC of `tos-service-native-registry-v1`, the code every public
/// registry object runs. `tos-service-native-registry-v1.release.json` pins its
/// code hash; a test holds this copy to that manifest.
pub const NATIVE_REGISTRY_RELEASE_CODE_B64: &str =
    include_str!("../../../../../crypto/smartcont/tos-service-native-registry-v1.boc.base64");

/// The release code cell.
pub fn native_registry_release_code() -> Result<Cell> {
    use anyhow::Context;
    let encoded: String = NATIVE_REGISTRY_RELEASE_CODE_B64.split_whitespace().collect();
    let bytes = chain_block::base64_decode(&encoded).context("native registry release base64")?;
    chain_block::read_single_root_boc(bytes).context("native registry release BOC")
}

/// Whether the contract requires counterparty signatures for `kind`: possession
/// of the policy a policy update or recovery initiation installs, and the
/// receiving owner's consent to a capability transfer.
pub fn native_kind_takes_counterparty(kind: u8) -> bool {
    matches!(
        kind,
        NATIVE_KIND_UPDATE_AGENT_POLICY
            | NATIVE_KIND_INITIATE_RECOVERY
            | NATIVE_KIND_TRANSFER_CAPABILITY
    )
}

/// The purpose a signer must hold for `kind` (the contract's `required_purpose`).
pub fn required_native_purpose(kind: u8) -> Result<u16> {
    match kind {
        NATIVE_KIND_REGISTER_AGENT | NATIVE_KIND_UPDATE_AGENT_POLICY | NATIVE_KIND_REVOKE_AGENT => {
            Ok(PURPOSE_AGENT_CONTROL)
        }
        NATIVE_KIND_DELEGATE_AGENT => Ok(PURPOSE_DELEGATION),
        NATIVE_KIND_INITIATE_RECOVERY | NATIVE_KIND_COMPLETE_RECOVERY => Ok(PURPOSE_RECOVERY),
        NATIVE_KIND_REGISTER_CAPABILITY..=NATIVE_KIND_REVOKE_CAPABILITY => {
            Ok(PURPOSE_CAPABILITY_CONTROL)
        }
        other => bail!("unknown native registry action kind {other}"),
    }
}

impl NativeRegistryDomain {
    /// The identity domain of one chain: its genesis root and file hashes, the
    /// SHA-256 of an explicit network label, and the runtime code hash. The
    /// label is never defaulted here; the caller names it.
    pub fn for_label(
        genesis_root: [u8; 32],
        genesis_file: [u8; 32],
        network_label: &[u8],
        runtime_code_hash: [u8; 32],
    ) -> Result<Self> {
        use sha2::{Digest, Sha256};
        anyhow::ensure!(
            (1..=127).contains(&network_label.len()),
            "native registry network label length"
        );
        anyhow::ensure!(
            network_label.iter().all(|b| (0x21..=0x7e).contains(b)),
            "native registry network label must be printable non-space ASCII"
        );
        let domain = NativeRegistryDomain {
            genesis_root,
            genesis_file,
            network_tag: Sha256::digest(network_label).into(),
            runtime_code_hash,
        };
        validate_native_domain(&domain)?;
        Ok(domain)
    }
}

/// Canonical protocol text (a version name): printable non-space ASCII,
/// 1..=128 bytes, as a minimal byte-aligned snake, with its SHA-256. The
/// contract's `validate_protocol_text` admits exactly this shape.
fn native_protocol_text(text: &[u8]) -> Result<([u8; 32], Cell)> {
    use anyhow::ensure;
    use sha2::{Digest, Sha256};
    ensure!((1..=128).contains(&text.len()), "native registry version length");
    ensure!(text.iter().all(|b| (0x21..=0x7e).contains(b)), "native registry version characters");
    let hash: [u8; 32] = Sha256::digest(text).into();
    let mut name = BuilderData::new();
    match text.split_at_checked(127) {
        Some((head, tail)) if !tail.is_empty() => {
            let mut rest = BuilderData::new();
            rest.append_raw(tail, tail.len() * 8)?;
            name.append_raw(head, 1016)?.checked_append_reference(rest.into_cell()?)?;
        }
        _ => {
            name.append_raw(text, text.len() * 8)?;
        }
    }
    Ok((hash, name.into_cell()?))
}

/// Payload of a policy update: the next policy (its controllers must all sign
/// as counterparty, proving possession).
pub fn build_native_update_policy_payload(next: &NativePolicy) -> Result<Cell> {
    let mut b = BuilderData::new();
    b.checked_append_reference(build_policy(next)?)?;
    Ok(b.into_cell()?)
}

/// Payload of a delegation: a nonzero 256-bit delegation id.
pub fn build_native_delegate_payload(delegation: [u8; 32]) -> Result<Cell> {
    anyhow::ensure!(delegation != [0; 32], "zero native registry delegation");
    let mut b = BuilderData::new();
    b.append_raw(&delegation, 256)?;
    Ok(b.into_cell()?)
}

/// Payload of a recovery initiation: the unix time after which it may complete
/// and the recovery policy (whose controllers all sign as counterparty). The
/// contract requires `execute_after >= now + current timelock` at execution.
pub fn build_native_initiate_recovery_payload(
    execute_after: u64,
    recovery: &NativePolicy,
) -> Result<Cell> {
    anyhow::ensure!(execute_after > 0, "zero native registry recovery time");
    let mut b = BuilderData::new();
    b.append_u64(execute_after)?.checked_append_reference(build_policy(recovery)?)?;
    Ok(b.into_cell()?)
}

/// Payload of a recovery completion: the hash of the initiating action.
pub fn build_native_complete_recovery_payload(initiation: [u8; 32]) -> Result<Cell> {
    anyhow::ensure!(initiation != [0; 32], "zero native registry recovery initiation");
    let mut b = BuilderData::new();
    b.append_raw(&initiation, 256)?;
    Ok(b.into_cell()?)
}

/// Payload of an Agent revocation: empty.
pub fn build_native_revoke_agent_payload() -> Result<Cell> {
    Ok(BuilderData::new().into_cell()?)
}

/// Payload of a new Capability version under its current owner Agent.
pub fn build_native_add_version_payload(
    owner_agent: [u8; 32],
    version: &[u8],
    manifest_digest: [u8; 32],
) -> Result<Cell> {
    anyhow::ensure!(owner_agent != [0; 32], "zero native registry capability owner");
    anyhow::ensure!(manifest_digest != [0; 32], "zero native registry manifest digest");
    let (version_hash, name) = native_protocol_text(version)?;
    let mut b = BuilderData::new();
    b.append_raw(&owner_agent, 256)?
        .append_raw(&version_hash, 256)?
        .append_raw(&manifest_digest, 256)?
        .checked_append_reference(name)?;
    Ok(b.into_cell()?)
}

/// Payload of a Capability transfer between two distinct owner Agents.
pub fn build_native_transfer_payload(old_owner: [u8; 32], new_owner: [u8; 32]) -> Result<Cell> {
    anyhow::ensure!(
        old_owner != [0; 32] && new_owner != [0; 32],
        "zero native registry capability owner"
    );
    anyhow::ensure!(old_owner != new_owner, "native registry transfer to the same owner");
    let mut b = BuilderData::new();
    b.append_raw(&old_owner, 256)?.append_raw(&new_owner, 256)?;
    Ok(b.into_cell()?)
}

/// Payload of a Capability revocation: the whole Capability (tombstone) when
/// `version` is `None`, otherwise that one version.
pub fn build_native_revoke_capability_payload(
    owner_agent: [u8; 32],
    version: Option<&[u8]>,
) -> Result<Cell> {
    anyhow::ensure!(owner_agent != [0; 32], "zero native registry capability owner");
    let mut b = BuilderData::new();
    b.append_raw(&owner_agent, 256)?;
    match version {
        None => {
            b.append_bit_zero()?;
        }
        Some(text) => {
            let (hash, name) = native_protocol_text(text)?;
            b.append_bit_one()?.append_raw(&hash, 256)?.checked_append_reference(name)?;
        }
    }
    Ok(b.into_cell()?)
}

fn next_bytes32(s: &mut chain_block::SliceData, what: &str) -> Result<[u8; 32]> {
    use anyhow::Context;
    s.get_next_bytes(32)?.try_into().ok().with_context(|| format!("{what} width"))
}

/// Decode a stored policy cell. Refuses anything that does not re-encode to the
/// identical cell through [`build_policy`], so a decoded policy is exactly one
/// the contract admits.
pub fn decode_native_policy(cell: &Cell) -> Result<NativePolicy> {
    use anyhow::ensure;
    use chain_block::SliceData;
    let mut s = SliceData::load_cell(cell.clone())?;
    ensure!(
        s.get_next_u32()? == MAGIC_POLICY && s.get_next_u16()? == POLICY_SCHEMA,
        "native registry policy tag or schema"
    );
    let threshold = s.get_next_u32()?;
    let recovery_threshold = s.get_next_u32()?;
    let recovery_timelock = s.get_next_u64()?;
    let count = usize::from(s.get_next_byte()?);
    ensure!(
        (1..=NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS).contains(&count),
        "native registry policy controller count"
    );
    let mut cursor = s.checked_drain_reference()?;
    ensure!(
        s.remaining_bits() == 0 && s.remaining_references() == 0,
        "native registry policy trailing data"
    );
    let mut controllers = Vec::with_capacity(count);
    for index in 0..count {
        let mut c = SliceData::load_cell(cursor.clone())?;
        let key_hash = next_bytes32(&mut c, "controller key hash")?;
        let public_key = next_bytes32(&mut c, "controller key")?;
        ensure!(key_hash == public_key, "native registry controller key hash");
        let weight = c.get_next_u32()?;
        let purposes = c.get_next_u16()?;
        let recovery = c.get_next_bit()?;
        ensure!(
            recovery == (purposes & PURPOSE_RECOVERY != 0),
            "native registry controller recovery flag"
        );
        let last = index.checked_add(1) == Some(count);
        if !last {
            cursor = c.checked_drain_reference()?;
        }
        ensure!(
            c.remaining_bits() == 0 && c.remaining_references() == 0,
            "native registry controller trailing data"
        );
        controllers.push(NativePolicyController { public_key, weight, purposes });
    }
    let policy = NativePolicy { threshold, recovery_threshold, recovery_timelock, controllers };
    ensure!(
        build_policy(&policy)?.repr_hash() == cell.repr_hash(),
        "native registry policy is not canonical"
    );
    Ok(policy)
}

/// Check, before anything is signed, that `signers` meet `policy` for `kind` the
/// way the contract's `verify_signatures` will: every signer a controller with
/// the required purpose (and the recovery flag for recovery kinds), no
/// duplicates, and the weight reaching the threshold (the recovery threshold
/// for recovery kinds).
pub fn check_native_threshold(policy: &NativePolicy, signers: &[[u8; 32]], kind: u8) -> Result<()> {
    use anyhow::ensure;
    let required = required_native_purpose(kind)?;
    let recovery_mode =
        matches!(kind, NATIVE_KIND_INITIATE_RECOVERY | NATIVE_KIND_COMPLETE_RECOVERY);
    ensure!(
        !signers.is_empty() && signers.len() <= NATIVE_REGISTRY_MAX_POLICY_CONTROLLERS,
        "native registry signer count"
    );
    let mut sorted = signers.to_vec();
    sorted.sort();
    ensure!(sorted.windows(2).all(|w| w[0] != w[1]), "duplicate native registry signer");
    let mut total: u64 = 0;
    for signer in &sorted {
        let controller =
            policy.controllers.iter().find(|c| c.public_key == *signer).ok_or_else(|| {
                anyhow::anyhow!("signer {} is not a controller", hex::encode(signer))
            })?;
        ensure!(
            controller.purposes & required != 0,
            "signer {} lacks the purpose action kind {kind} requires",
            hex::encode(signer)
        );
        if recovery_mode {
            ensure!(
                controller.purposes & PURPOSE_RECOVERY != 0,
                "signer {} is not a recovery controller",
                hex::encode(signer)
            );
        }
        total = total
            .checked_add(u64::from(controller.weight))
            .ok_or_else(|| anyhow::anyhow!("signer weight total overflows"))?;
    }
    let wanted =
        u64::from(if recovery_mode { policy.recovery_threshold } else { policy.threshold });
    ensure!(total >= wanted, "signer weight {total} is below the threshold {wanted}");
    Ok(())
}

/// Check that `signers` is exactly the controller set of `policy`: the contract
/// requires a possession signature from every controller of a policy it installs.
pub fn check_native_possession(policy: &NativePolicy, signers: &[[u8; 32]]) -> Result<()> {
    let mut wanted: Vec<[u8; 32]> = policy.controllers.iter().map(|c| c.public_key).collect();
    wanted.sort();
    let mut given = signers.to_vec();
    given.sort();
    anyhow::ensure!(
        wanted == given,
        "possession needs a signature from exactly every controller of the installed policy"
    );
    Ok(())
}

/// A pending recovery stored on an Agent.
#[derive(Clone, Debug)]
pub struct NativePendingRecovery {
    pub initiation: [u8; 32],
    pub old_policy_hash: [u8; 32],
    pub execute_after: u64,
    pub policy: Cell,
}

/// Kind-specific part of a stored registry object.
#[derive(Clone, Debug)]
pub enum NativeRegistryStateDetail {
    Agent {
        policy: Cell,
        delegations: u16,
        delegation_root: Option<Cell>,
        recovery: Option<NativePendingRecovery>,
    },
    Capability {
        owner: [u8; 32],
        versions: u16,
        version_root: Option<Cell>,
    },
}

/// A registry object's stored state, as returned by `get_native_state`.
#[derive(Clone, Debug)]
pub struct NativeRegistryState {
    pub object_kind: u8,
    pub tombstone: bool,
    pub generation: u64,
    pub sequence: u64,
    pub last_action: [u8; 32],
    /// Hash of the exact state cell: the predecessor of the next action.
    pub state_hash: [u8; 32],
    pub detail: NativeRegistryStateDetail,
}

fn decode_counted_dict(cell: Cell, what: &str) -> Result<(u16, Option<Cell>)> {
    use anyhow::ensure;
    use chain_block::SliceData;
    let mut s = SliceData::load_cell(cell)?;
    let count = s.get_next_u16()?;
    let root = if s.get_next_bit()? { Some(s.checked_drain_reference()?) } else { None };
    ensure!(s.remaining_bits() == 0 && s.remaining_references() == 0, "{what} trailing data");
    Ok((count, root))
}

/// Decode a stored registry state cell (the contract's NVS1 layout).
pub fn decode_native_registry_state(state: &Cell) -> Result<NativeRegistryState> {
    use anyhow::ensure;
    use chain_block::SliceData;
    let mut s = SliceData::load_cell(state.clone())?;
    ensure!(
        s.get_next_u32()? == MAGIC_STATE && s.get_next_u16()? == STATE_SCHEMA,
        "native registry state tag or schema"
    );
    let object_kind = s.get_next_byte()?;
    let tombstone = s.get_next_bit()?;
    let generation = s.get_next_u64()?;
    let sequence = s.get_next_u64()?;
    let last_action = next_bytes32(&mut s, "last action")?;
    let detail = match object_kind {
        1 => {
            let policy = s.checked_drain_reference()?;
            let (delegations, delegation_root) =
                decode_counted_dict(s.checked_drain_reference()?, "native registry delegations")?;
            let mut r = SliceData::load_cell(s.checked_drain_reference()?)?;
            let recovery = if r.get_next_bit()? {
                let initiation = next_bytes32(&mut r, "recovery initiation")?;
                let old_policy_hash = next_bytes32(&mut r, "recovery policy hash")?;
                let execute_after = r.get_next_u64()?;
                let policy = r.checked_drain_reference()?;
                Some(NativePendingRecovery { initiation, old_policy_hash, execute_after, policy })
            } else {
                None
            };
            ensure!(
                r.remaining_bits() == 0 && r.remaining_references() == 0,
                "native registry recovery trailing data"
            );
            NativeRegistryStateDetail::Agent { policy, delegations, delegation_root, recovery }
        }
        2 => {
            let owner = next_bytes32(&mut s, "capability owner")?;
            let (versions, version_root) =
                decode_counted_dict(s.checked_drain_reference()?, "native registry versions")?;
            NativeRegistryStateDetail::Capability { owner, versions, version_root }
        }
        other => bail!("unknown native registry object kind {other}"),
    };
    ensure!(
        s.remaining_bits() == 0 && s.remaining_references() == 0,
        "native registry state trailing data"
    );
    Ok(NativeRegistryState {
        object_kind,
        tombstone,
        generation,
        sequence,
        last_action,
        state_hash: *state.repr_hash().as_array(),
        detail,
    })
}

/// Whether a 256-bit key is present in a stored delegation or version dictionary.
pub fn native_dict_contains(root: &Option<Cell>, key: &[u8; 32]) -> Result<bool> {
    use chain_block::{HashmapE, SliceData};
    let map = HashmapE::with_hashmap(256, root.clone());
    Ok(map.get(SliceData::from_raw(key.to_vec(), 256))?.is_some())
}

/// One stored Capability version.
#[derive(Clone, Debug)]
pub struct NativeCapabilityVersion {
    pub manifest_digest: [u8; 32],
    pub revoked: bool,
    pub name: Cell,
}

/// The stored version `version_hash` of a Capability's version dictionary
/// (`manifest:uint256 revoked:Bool ^name`), `None` when absent.
pub fn native_capability_version(
    root: &Option<Cell>,
    version_hash: &[u8; 32],
) -> Result<Option<NativeCapabilityVersion>> {
    use chain_block::{HashmapE, SliceData};
    let map = HashmapE::with_hashmap(256, root.clone());
    let Some(mut entry) = map.get(SliceData::from_raw(version_hash.to_vec(), 256))? else {
        return Ok(None);
    };
    let manifest_digest = next_bytes32(&mut entry, "version manifest")?;
    let revoked = entry.get_next_bit()?;
    let name = entry.checked_drain_reference()?;
    anyhow::ensure!(
        entry.remaining_bits() == 0 && entry.remaining_references() == 0,
        "native registry version trailing data"
    );
    Ok(Some(NativeCapabilityVersion { manifest_digest, revoked, name }))
}

/// The generation, sequence and predecessor the next action of `kind` must
/// carry on an object whose current state is `current` (`None`: not yet
/// registered), following the contract's rules: a registration starts at
/// (1, 1, zero); recovery completion and capability transfer start the next
/// generation at sequence 1; every other kind increments the sequence. The
/// predecessor is the hash of the exact current state cell.
pub fn next_native_position(
    current: Option<&NativeRegistryState>,
    kind: u8,
) -> Result<(u64, u64, [u8; 32])> {
    use anyhow::ensure;
    ensure!((1..=10).contains(&kind), "unknown native registry action kind {kind}");
    let target = if kind <= NATIVE_KIND_REVOKE_AGENT { 1 } else { 2 };
    let registration = matches!(kind, NATIVE_KIND_REGISTER_AGENT | NATIVE_KIND_REGISTER_CAPABILITY);
    match current {
        None => {
            ensure!(registration, "native registry object is not registered");
            Ok((1, 1, [0; 32]))
        }
        Some(state) => {
            ensure!(!registration, "native registry object is already registered");
            ensure!(state.object_kind == target, "action kind {kind} targets another object kind");
            ensure!(!state.tombstone, "native registry object is revoked");
            if matches!(kind, NATIVE_KIND_COMPLETE_RECOVERY | NATIVE_KIND_TRANSFER_CAPABILITY) {
                let generation = state
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("native registry generation overflows"))?;
                Ok((generation, 1, state.state_hash))
            } else {
                let sequence = state
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("native registry sequence overflows"))?;
                Ok((state.generation, sequence, state.state_hash))
            }
        }
    }
}

#[cfg(test)]
mod lifecycle_builder_tests {
    use super::*;
    use chain_block::SliceData;

    fn key(seed: u8) -> [u8; 32] {
        // Deliberately public deterministic test fixture, never an operational key.
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    fn policy(keys: &[(u8, u32, u16)], threshold: u32, recovery: u32) -> NativePolicy {
        NativePolicy {
            threshold,
            recovery_threshold: recovery,
            recovery_timelock: 60,
            controllers: keys
                .iter()
                .map(|&(seed, weight, purposes)| NativePolicyController {
                    public_key: key(seed),
                    weight,
                    purposes,
                })
                .collect(),
        }
    }

    #[test]
    fn release_code_matches_the_release_manifest() -> Result<()> {
        use sha2::{Digest, Sha256};
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../crypto/smartcont/tos-service-native-registry-v1.release.json"
        ))?;
        let code = native_registry_release_code()?;
        assert_eq!(
            manifest["code_hash"].as_str(),
            Some(format!("tvm-cell-sha256:{}", hex::encode(code.repr_hash().as_slice())).as_str())
        );
        let encoded: String = NATIVE_REGISTRY_RELEASE_CODE_B64.split_whitespace().collect();
        let bytes = chain_block::base64_decode(&encoded)?;
        assert_eq!(manifest["boc_bytes"].as_u64(), Some(u64::try_from(bytes.len())?));
        assert_eq!(
            manifest["boc_sha256"].as_str(),
            Some(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))).as_str())
        );
        Ok(())
    }

    #[test]
    fn public_domain_label_is_explicit_and_bound() -> Result<()> {
        let code = native_registry_release_code()?;
        let d = NativeRegistryDomain::for_label(
            [1; 32],
            [2; 32],
            b"tos:global-id:2",
            *code.repr_hash().as_array(),
        )?;
        assert_eq!(
            hex::encode(d.network_tag),
            "867b460108f617ef4508e406addf30db563dbabf44f7e90e58cff93ddeacf4a9"
        );
        for bad in [&b""[..], &b"tos global"[..], &[b'a'; 128][..], &[0x80][..]] {
            assert!(NativeRegistryDomain::for_label([1; 32], [2; 32], bad, [3; 32]).is_err());
        }
        assert!(NativeRegistryDomain::for_label([0; 32], [2; 32], b"x", [3; 32]).is_err());
        Ok(())
    }

    #[test]
    fn payloads_follow_the_contract_parse() -> Result<()> {
        let p = policy(&[(1, 1, 15)], 1, 1);
        let mut s = SliceData::load_cell(build_native_update_policy_payload(&p)?)?;
        assert_eq!(s.checked_drain_reference()?, build_policy(&p)?);
        assert!(s.remaining_bits() == 0 && s.remaining_references() == 0);

        let mut s = SliceData::load_cell(build_native_delegate_payload([7; 32])?)?;
        assert_eq!(s.get_next_bytes(32)?, vec![7; 32]);
        assert_eq!(s.remaining_bits(), 0);

        let mut s = SliceData::load_cell(build_native_initiate_recovery_payload(99, &p)?)?;
        assert_eq!(s.get_next_u64()?, 99);
        assert_eq!(s.checked_drain_reference()?, build_policy(&p)?);
        assert!(s.remaining_bits() == 0 && s.remaining_references() == 0);

        let mut s = SliceData::load_cell(build_native_complete_recovery_payload([8; 32])?)?;
        assert_eq!(s.get_next_bytes(32)?, vec![8; 32]);
        assert_eq!(s.remaining_bits(), 0);

        let s = SliceData::load_cell(build_native_revoke_agent_payload()?)?;
        assert!(s.remaining_bits() == 0 && s.remaining_references() == 0);

        let (hash, name) = native_protocol_text(b"1.1.0")?;
        let mut s =
            SliceData::load_cell(build_native_add_version_payload([4; 32], b"1.1.0", [5; 32])?)?;
        assert_eq!(s.get_next_bytes(32)?, vec![4; 32]);
        assert_eq!(s.get_next_bytes(32)?, hash.to_vec());
        assert_eq!(s.get_next_bytes(32)?, vec![5; 32]);
        assert_eq!(s.checked_drain_reference()?, name);
        assert!(s.remaining_bits() == 0 && s.remaining_references() == 0);

        let mut s = SliceData::load_cell(build_native_transfer_payload([4; 32], [6; 32])?)?;
        assert_eq!(s.get_next_bytes(32)?, vec![4; 32]);
        assert_eq!(s.get_next_bytes(32)?, vec![6; 32]);
        assert_eq!(s.remaining_bits(), 0);

        let mut s = SliceData::load_cell(build_native_revoke_capability_payload([4; 32], None)?)?;
        assert_eq!(s.get_next_bytes(32)?, vec![4; 32]);
        assert!(!s.get_next_bit()?);
        assert!(s.remaining_bits() == 0 && s.remaining_references() == 0);
        let mut s =
            SliceData::load_cell(build_native_revoke_capability_payload([4; 32], Some(b"1.1.0"))?)?;
        s.get_next_bytes(32)?;
        assert!(s.get_next_bit()?);
        assert_eq!(s.get_next_bytes(32)?, hash.to_vec());
        assert_eq!(s.checked_drain_reference()?, name);
        assert!(s.remaining_bits() == 0 && s.remaining_references() == 0);
        Ok(())
    }

    #[test]
    fn payloads_refuse_zero_identities_and_self_transfer() {
        assert!(build_native_delegate_payload([0; 32]).is_err());
        assert!(build_native_complete_recovery_payload([0; 32]).is_err());
        assert!(build_native_initiate_recovery_payload(0, &policy(&[(1, 1, 15)], 1, 1)).is_err());
        assert!(build_native_add_version_payload([0; 32], b"1", [5; 32]).is_err());
        assert!(build_native_add_version_payload([4; 32], b"1", [0; 32]).is_err());
        assert!(build_native_add_version_payload([4; 32], b"has space", [5; 32]).is_err());
        assert!(build_native_transfer_payload([4; 32], [4; 32]).is_err());
        assert!(build_native_transfer_payload([0; 32], [4; 32]).is_err());
        assert!(build_native_revoke_capability_payload([0; 32], None).is_err());
    }

    #[test]
    fn policy_decoder_round_trips_and_refuses_non_canonical() -> Result<()> {
        let p = policy(&[(1, 2, 15), (2, 1, 1), (3, 5, 12)], 2, 5);
        let cell = build_policy(&p)?;
        let mut sorted = p.clone();
        sorted.controllers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert_eq!(decode_native_policy(&cell)?, sorted);
        // A recovery flag that disagrees with the purposes is refused.
        let header_bits = 32 + 16 + 32 + 32 + 64 + 8;
        let field_bits = 256 + 256 + 32 + 16;
        let mut root = SliceData::load_cell(cell)?;
        let header = root.get_next_bits(header_bits)?;
        let mut c = SliceData::load_cell(root.checked_drain_reference()?)?;
        let fields = c.get_next_bits(field_bits)?;
        let flag = c.get_next_bit()?;
        let link = c.checked_drain_reference()?;
        let mut forged = BuilderData::new();
        forged.append_raw(&fields, field_bits)?.append_bit_bool(!flag)?;
        forged.checked_append_reference(link)?;
        let mut forged_root = BuilderData::new();
        forged_root.append_raw(&header, header_bits)?;
        forged_root.checked_append_reference(forged.into_cell()?)?;
        assert!(decode_native_policy(&forged_root.into_cell()?).is_err());
        Ok(())
    }

    #[test]
    fn threshold_and_possession_checks_mirror_the_contract() -> Result<()> {
        // Weights: agent control 1+2 = 3, delegation 2 (key 1 only), capability
        // control 2+5 = 7, recovery 2+5 = 7; threshold 2, recovery threshold 5.
        let p = policy(&[(1, 2, 15), (2, 1, 1), (3, 5, 12)], 2, 5);
        check_native_threshold(&p, &[key(1)], NATIVE_KIND_REVOKE_AGENT)?;
        check_native_threshold(&p, &[key(1), key(2)], NATIVE_KIND_REVOKE_AGENT)?;
        assert!(check_native_threshold(&p, &[key(2)], NATIVE_KIND_REVOKE_AGENT).is_err());
        assert!(check_native_threshold(&p, &[key(1), key(1)], NATIVE_KIND_REVOKE_AGENT).is_err());
        assert!(check_native_threshold(&p, &[key(9)], NATIVE_KIND_REVOKE_AGENT).is_err());
        check_native_threshold(&p, &[key(1)], NATIVE_KIND_DELEGATE_AGENT)?;
        // Controller 2 holds agent control only, so it cannot sign a delegation.
        assert!(check_native_threshold(&p, &[key(1), key(2)], NATIVE_KIND_DELEGATE_AGENT).is_err());
        check_native_threshold(&p, &[key(3)], NATIVE_KIND_COMPLETE_RECOVERY)?;
        assert!(check_native_threshold(&p, &[key(1)], NATIVE_KIND_INITIATE_RECOVERY).is_err());
        check_native_threshold(&p, &[key(3)], NATIVE_KIND_ADD_CAPABILITY_VERSION)?;
        assert!(check_native_threshold(&p, &[], NATIVE_KIND_REVOKE_AGENT).is_err());
        check_native_possession(&p, &[key(3), key(1), key(2)])?;
        assert!(check_native_possession(&p, &[key(1), key(2)]).is_err());
        assert!(check_native_possession(&p, &[key(1), key(2), key(3), key(4)]).is_err());
        Ok(())
    }

    fn agent_state(tombstone: bool, generation: u64, sequence: u64) -> Result<Cell> {
        let p = build_policy(&policy(&[(1, 1, 15)], 1, 1))?;
        let mut delegations = BuilderData::new();
        delegations.append_u16(0)?.append_bit_zero()?;
        let mut recovery = BuilderData::new();
        recovery.append_bit_zero()?;
        let mut b = BuilderData::new();
        b.append_u32(MAGIC_STATE)?
            .append_u16(1)?
            .append_u8(1)?
            .append_bit_bool(tombstone)?
            .append_u64(generation)?
            .append_u64(sequence)?
            .append_raw(&[9; 32], 256)?;
        b.checked_append_reference(p)?;
        b.checked_append_reference(delegations.into_cell()?)?;
        b.checked_append_reference(recovery.into_cell()?)?;
        Ok(b.into_cell()?)
    }

    #[test]
    fn next_position_follows_generation_and_sequence_rules() -> Result<()> {
        assert_eq!(next_native_position(None, NATIVE_KIND_REGISTER_AGENT)?, (1, 1, [0; 32]));
        assert!(next_native_position(None, NATIVE_KIND_DELEGATE_AGENT).is_err());
        let cell = agent_state(false, 3, 7)?;
        let state = decode_native_registry_state(&cell)?;
        assert_eq!((state.generation, state.sequence, state.last_action), (3, 7, [9; 32]));
        let hash = *cell.repr_hash().as_array();
        assert_eq!(next_native_position(Some(&state), NATIVE_KIND_DELEGATE_AGENT)?, (3, 8, hash));
        assert_eq!(
            next_native_position(Some(&state), NATIVE_KIND_COMPLETE_RECOVERY)?,
            (4, 1, hash)
        );
        assert!(next_native_position(Some(&state), NATIVE_KIND_REGISTER_AGENT).is_err());
        assert!(next_native_position(Some(&state), NATIVE_KIND_ADD_CAPABILITY_VERSION).is_err());
        let revoked = decode_native_registry_state(&agent_state(true, 3, 7)?)?;
        assert!(next_native_position(Some(&revoked), NATIVE_KIND_DELEGATE_AGENT).is_err());
        let full = decode_native_registry_state(&agent_state(false, 3, u64::MAX)?)?;
        assert!(next_native_position(Some(&full), NATIVE_KIND_DELEGATE_AGENT).is_err());
        Ok(())
    }

    #[test]
    fn counterparty_consent_is_required_exactly_where_the_contract_requires_it() -> Result<()> {
        use ed25519_dalek::Signer;
        let d = NativeRegistryDomain {
            genesis_root: [1; 32],
            genesis_file: [2; 32],
            network_tag: [3; 32],
            runtime_code_hash: [4; 32],
        };
        let signer = ed25519_dalek::SigningKey::from_bytes(&[70; 32]);
        for kind in 1..=10u8 {
            let action = build_native_action(
                &d,
                &NativeRegistryAction {
                    kind,
                    generation: 1,
                    sequence: 1,
                    object_id: [5; 32],
                    predecessor: [0; 32],
                    nonce: [6; 32],
                    payload: Cell::default(),
                },
            )?;
            let sig = NativeControllerSignature {
                public_key: signer.verifying_key().to_bytes(),
                signature: signer.sign(action.repr_hash().as_slice()).to_bytes(),
            };
            let without = build_native_submission(&d, &action, 1, &[sig.clone()], &[]);
            let with = build_native_submission(&d, &action, 1, &[sig.clone()], &[sig]);
            assert_eq!(without.is_ok(), !native_kind_takes_counterparty(kind), "kind {kind}");
            assert_eq!(with.is_ok(), native_kind_takes_counterparty(kind), "kind {kind}");
        }
        let zero = NativeRegistryAction {
            kind: 1,
            generation: 1,
            sequence: 1,
            object_id: [0; 32],
            predecessor: [0; 32],
            nonce: [6; 32],
            payload: Cell::default(),
        };
        assert!(build_native_action(&d, &zero).is_err());
        Ok(())
    }
}
