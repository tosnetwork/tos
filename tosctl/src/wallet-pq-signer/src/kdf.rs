// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Fixed new-wallet derivation. The caller supplies a validated 32-byte native
//! mnemonic master or raw master, never a daily signing seed. Domain separation
//! does not provide independent-device custody. Fee derivation does not restore
//! an LMS leaf journal or authorize reuse of a tree.
use crate::{Rejected, Role, Signer, WipeSeed};
use openssl::{
    md::Md,
    pkey::Id,
    pkey_ctx::{HkdfMode, PkeyCtx},
};
use zeroize::{Zeroize, Zeroizing};

pub const PROFILE: &[u8] = b"TOS-WALLET-DUALROOT-KDF-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivationContext {
    pub network: [u8; 32],
    pub global_id: i32,
    pub account_index: u32,
    pub key_generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Material {
    Primary,
    Rescue,
    /// Public independent random tree identity. Restoring a known tree must use
    /// its enrolled identity; replacement requires a newly generated identity.
    Fee {
        tree_id: [u8; 32],
    },
}

impl Material {
    pub fn seed_bytes(self) -> usize {
        match self {
            Self::Primary => 32,
            Self::Rescue | Self::Fee { .. } => 48,
        }
    }
    fn info(self, context: DerivationContext) -> Vec<u8> {
        let label: &[u8] = match self {
            Self::Primary => b"ML-DSA-44",
            Self::Rescue => b"SLH-DSA-SHA2-128s",
            Self::Fee { .. } => b"TOS-FEE-LMS-SHA256-M32-v1",
        };
        let mut info = vec![1, label.len() as u8];
        info.extend_from_slice(label);
        info.extend_from_slice(&context.network);
        info.extend_from_slice(&context.global_id.to_be_bytes());
        info.extend_from_slice(&context.account_index.to_be_bytes());
        info.extend_from_slice(&context.key_generation.to_be_bytes());
        if let Self::Fee { tree_id } = self {
            info.extend_from_slice(&tree_id);
        }
        info
    }
}

/// Derive into caller-owned secret storage, wiping the supplied master on every
/// return path. Output is cleared before validation and remains zero on failure.
/// Sizes are exact: 32 primary, 48 rescue (SK.seed || SK.prf || PK.seed), or 48
/// fee (SEED || I). Caller must protect and wipe successful output after use.
pub fn derive_seed_and_wipe(
    master: &mut [u8],
    context: DerivationContext,
    material: Material,
    output: &mut [u8],
) -> Result<(), Rejected> {
    let master = WipeSeed(master);
    output.zeroize();
    if master.0.len() != 32 || output.len() != material.seed_bytes() {
        return Err(Rejected);
    }
    let mut temporary = Zeroizing::new([0u8; 48]);
    let size = material.seed_bytes();
    let mut kdf = PkeyCtx::new_id(Id::HKDF).map_err(|_| Rejected)?;
    kdf.derive_init().map_err(|_| Rejected)?;
    kdf.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND).map_err(|_| Rejected)?;
    kdf.set_hkdf_md(Md::sha256()).map_err(|_| Rejected)?;
    kdf.set_hkdf_salt(PROFILE).map_err(|_| Rejected)?;
    kdf.set_hkdf_key(master.0).map_err(|_| Rejected)?;
    kdf.add_hkdf_info(&material.info(context)).map_err(|_| Rejected)?;
    let written = kdf.derive(Some(&mut temporary[..size])).map_err(|_| Rejected)?;
    if written != size {
        return Err(Rejected);
    }
    output.copy_from_slice(&temporary[..size]);
    Ok(())
}

/// Derive a native PQ signer without exporting its seed. For separate masters,
/// invoke this independently on the appropriate custody device with the same
/// public generation. No legacy mnemonic/key mapping is changed.
pub fn derive_signer_and_wipe(
    master: &mut [u8],
    context: DerivationContext,
    role: Role,
) -> Result<Signer, Rejected> {
    let material = match role {
        Role::Primary => Material::Primary,
        Role::Rescue => Material::Rescue,
    };
    let mut seed = Zeroizing::new([0u8; 48]);
    let seed = &mut seed[..material.seed_bytes()];
    derive_seed_and_wipe(master, context, material, seed)?;
    Signer::import_and_wipe(role, seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }
    fn context(root: &Value, vector: &Value) -> DerivationContext {
        DerivationContext {
            network: bytes(&root["inputs"]["network_tag_hex"]).try_into().unwrap(),
            global_id: root["inputs"]["global_id"].as_i64().unwrap().try_into().unwrap(),
            account_index: vector["account_index"].as_u64().unwrap().try_into().unwrap(),
            key_generation: vector["key_generation"].as_u64().unwrap().try_into().unwrap(),
        }
    }

    #[test]
    fn frozen_dual_root_and_fee_vectors() {
        let dual: Value =
            serde_json::from_str(include_str!("../tests/fixtures/dual-root-kdf.json")).unwrap();
        let fee: Value = serde_json::from_str(include_str!(
            "../../../../test/rescue-fee-gate/fee-kdf-vectors.json"
        ))
        .unwrap();
        let mut checked = 0;
        for root in [&dual, &fee] {
            for vector in root["vectors"].as_array().unwrap() {
                let context = context(root, vector);
                let materials = if vector.get("outputs").is_some() {
                    vec![Material::Primary, Material::Rescue]
                } else {
                    vec![Material::Fee {
                        tree_id: bytes(&vector["fee_tree_id_hex"]).try_into().unwrap(),
                    }]
                };
                for material in materials {
                    let (info, expected) = match material {
                        Material::Primary => (
                            &vector["outputs"]["ML-DSA-44"]["info_hex"],
                            bytes(&vector["outputs"]["ML-DSA-44"]["material_hex"]),
                        ),
                        Material::Rescue => (
                            &vector["outputs"]["SLH-DSA-SHA2-128s"]["info_hex"],
                            bytes(&vector["outputs"]["SLH-DSA-SHA2-128s"]["material_hex"]),
                        ),
                        Material::Fee { .. } => {
                            let mut seed = bytes(&vector["SEED_hex"]);
                            seed.extend(bytes(&vector["I_hex"]));
                            (&vector["info_hex"], seed)
                        }
                    };
                    assert_eq!(material.info(context), bytes(info), "KDF info bytes changed");
                    let mut master = bytes(&root["inputs"]["master_hex"]);
                    let mut output = vec![0xa5; material.seed_bytes()];
                    derive_seed_and_wipe(&mut master, context, material, &mut output).unwrap();
                    assert_eq!(master, [0; 32], "master not wiped after derivation");
                    assert_eq!(output, expected, "KDF output differs from frozen vector");
                    if let Material::Primary | Material::Rescue = material {
                        let role = if material == Material::Primary {
                            Role::Primary
                        } else {
                            Role::Rescue
                        };
                        let mut master = bytes(&root["inputs"]["master_hex"]);
                        let signer = derive_signer_and_wipe(&mut master, context, role).unwrap();
                        let expected = Signer::import_and_wipe(role, &mut output).unwrap();
                        assert_eq!(signer.public_key(), expected.public_key());
                        assert_eq!(master, [0; 32]);
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 7);
    }

    #[test]
    fn rejected_sizes_clear_master_and_output() {
        let context = DerivationContext {
            network: [1; 32],
            global_id: -1,
            account_index: 0,
            key_generation: 0,
        };
        for material in [Material::Primary, Material::Rescue, Material::Fee { tree_id: [2; 32] }] {
            for (master_len, out_len) in
                [(31, material.seed_bytes()), (33, material.seed_bytes()), (32, 31), (32, 49)]
            {
                let mut master = vec![0x55; master_len];
                let mut output = vec![0xa5; out_len];
                assert!(
                    derive_seed_and_wipe(&mut master, context, material, &mut output).is_err(),
                    "invalid KDF width accepted"
                );
                assert!(master.iter().all(|b| *b == 0), "master not wiped on rejection");
                assert!(output.iter().all(|b| *b == 0), "failed derivation retained output");
            }
        }
    }

    #[test]
    fn namespace_fields_separate_outputs() {
        let context = DerivationContext {
            network: [1; 32],
            global_id: -239,
            account_index: 0,
            key_generation: 0,
        };
        let cases = [
            context,
            DerivationContext { network: [2; 32], ..context },
            DerivationContext { global_id: 239, ..context },
            DerivationContext { account_index: u32::MAX, ..context },
            DerivationContext { key_generation: u32::MAX, ..context },
        ];
        for material in [Material::Primary, Material::Rescue, Material::Fee { tree_id: [2; 32] }] {
            let mut observed = std::collections::HashSet::new();
            for context in cases {
                let mut output = vec![0; material.seed_bytes()];
                derive_seed_and_wipe(&mut [0x55; 32], context, material, &mut output).unwrap();
                assert!(observed.insert(output), "KDF namespace collision");
            }
        }
    }
}
