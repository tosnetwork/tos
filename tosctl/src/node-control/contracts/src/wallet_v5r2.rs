// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! PQ-only V5R2 AUTH wire construction, independent of custody and transport.
//!
//! This encoder checks the strict send-action list, but does not verify chain
//! proofs, installed code or signatures. The caller must obtain counters from trusted current
//! state and validate migration witnesses before requesting a signature. The
//! module and receiving wallet enforce those checks again on chain.
use chain_block::{BuilderData, Cell, IBitstring, SliceData};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthRole {
    Primary,
    Rescue,
}

impl AuthRole {
    pub fn signing_context(self) -> &'static [u8] {
        match self {
            Self::Primary => b"TOS-AUTH-V2-ML-DSA-44-v1",
            Self::Rescue => b"TOS-AUTH-SLH-DSA-SHA2-128S-v1",
        }
    }

    pub fn signature_bytes(self) -> usize {
        match self {
            Self::Primary => 2420,
            Self::Rescue => 7856,
        }
    }
}

/// Canonical envelopes. Referenced actions and StateInit witnesses remain
/// subject to full receiving-contract validation; construction is not approval.
pub enum AuthAction {
    Execute { actions: Cell },
    Configure { fee_replacement: Option<(Cell, Cell)> },
    LockPrimary,
    Migrate { module_init: Cell, metadata: Cell, vault_init: Cell },
}

impl AuthAction {
    fn encode(self) -> anyhow::Result<(u8, Cell)> {
        let mut b = BuilderData::new();
        let kind = match self {
            Self::Execute { actions } => {
                validate_actions(&actions)?;
                b.append_u32(0x45584543)?;
                b.checked_append_reference(actions)?;
                0
            }
            Self::Configure { fee_replacement } => {
                b.append_u32(0x434f4e46)?;
                b.append_raw(&[0x80], 2)?; // Only PQ mode 2, never hybrid mode 3.
                if let Some((metadata, vault_init)) = fee_replacement {
                    let mut replacement = BuilderData::new();
                    replacement.checked_append_reference(metadata)?;
                    replacement.checked_append_reference(vault_init)?;
                    b.append_bit_one()?;
                    b.checked_append_reference(replacement.into_cell()?)?;
                } else {
                    b.append_bit_zero()?;
                }
                1
            }
            Self::LockPrimary => {
                b.append_u32(0x4c4f434b)?;
                b.append_u8(1)?; // ML-DSA-44 is the only primary suite.
                3
            }
            Self::Migrate { module_init, metadata, vault_init } => {
                b.append_u32(0x4d494752)?;
                b.checked_append_reference(module_init)?;
                b.checked_append_reference(metadata)?;
                b.checked_append_reference(vault_init)?;
                4
            }
        };
        Ok((kind, b.into_cell()?))
    }
}

/// Validate the V5 strict AUTH OutList before exposing a signing digest.
/// Message contents, available funds and delivery remain execution-time checks;
/// this is not approval of a recipient, amount or message body by the owner.
pub fn validate_actions(actions: &Cell) -> anyhow::Result<()> {
    let mut current = actions.clone();
    let mut count = 0u16;
    loop {
        let mut slice = SliceData::load_cell(current)?;
        if slice.remaining_bits() == 0 {
            anyhow::ensure!(slice.remaining_references() == 0, "action tail must be empty");
            return Ok(());
        }
        anyhow::ensure!(count < 255, "at most 255 send actions");
        anyhow::ensure!(
            slice.remaining_bits() == 40 && slice.remaining_references() == 2,
            "send action shape"
        );
        anyhow::ensure!(slice.get_next_u32()? == 0x0ec3c86d, "only send actions are allowed");
        let mode = slice.get_next_byte()?;
        anyhow::ensure!(mode & 2 != 0, "send action requires ignore-errors flag");
        anyhow::ensure!(mode & 44 == 0, "forbidden send mode flags");
        anyhow::ensure!(mode & 192 != 192, "conflicting send value modes");
        current = slice.checked_drain_reference()?;
        count = count.checked_add(1).ok_or_else(|| anyhow::anyhow!("action count overflow"))?;
    }
}

/// Account/module hashes are basechain standard addresses without anycast.
/// Their code identity and pairing must be verified separately.
pub struct AuthBinding {
    pub global_id: i32,
    pub network: [u8; 32],
    pub account: [u8; 32],
    pub module: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub valid_until: u32,
}

/// Immutable request: the digest, role context and encoded submission always
/// refer to the same bytes. There is no classic signature or cosignature field.
pub struct AuthRequest {
    cell: Cell,
    role: AuthRole,
    digest: [u8; 32],
}

impl AuthRequest {
    /// `proven_time` must come from a fresh verified chain view, not local time.
    pub fn new(
        binding: AuthBinding,
        role: AuthRole,
        action: AuthAction,
        proven_time: u32,
    ) -> anyhow::Result<Self> {
        let ttl = binding
            .valid_until
            .checked_sub(proven_time)
            .ok_or_else(|| anyhow::anyhow!("expired AUTH deadline"))?;
        anyhow::ensure!((1..=3600).contains(&ttl), "AUTH TTL must be 1..=3600 seconds");
        anyhow::ensure!(binding.account != binding.module, "wallet and module must differ");
        let (kind, payload) = action.encode()?;
        anyhow::ensure!(role != AuthRole::Primary || kind == 0, "primary may only execute");
        let mut b = BuilderData::new();
        b.append_u32(0x41553252)?;
        b.append_i32(binding.global_id)?;
        b.append_u256(&binding.network)?;
        b.append_raw(&[0x80, 0], 11)?; // addr_std, no anycast, workchain zero.
        b.append_u256(&binding.account)?;
        b.append_u256(&binding.module)?;
        b.append_u8(match role {
            AuthRole::Primary => 1,
            AuthRole::Rescue => 2,
        })?;
        b.append_u64(binding.epoch)?;
        b.append_u64(binding.nonce)?;
        b.append_u32(binding.valid_until)?;
        b.append_u8(kind)?;
        b.checked_append_reference(payload)?;
        let cell = b.into_cell()?;
        let mut domain = BuilderData::new();
        domain.append_raw(b"TOS-AUTH", 64)?;
        domain.checked_append_reference(cell.clone())?;
        let digest = *domain.into_cell()?.repr_hash().as_array();
        Ok(Self { cell, role, digest })
    }

    pub fn cell(&self) -> &Cell {
        &self.cell
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn role(&self) -> AuthRole {
        self.role
    }
    pub fn signing_context(&self) -> &'static [u8] {
        self.role.signing_context()
    }

    /// Encode SUB3 for an internal message to the module. This checks framing,
    /// not cryptographic validity; it must not be treated as signature approval.
    pub fn encode_submission(&self, signature: &[u8]) -> anyhow::Result<Cell> {
        encode_pq_submission(0x53554233, &self.cell, self.role, signature)
    }
}

/// Framing only; callers must verify cryptographic signatures separately.
pub(crate) fn encode_pq_submission(
    tag: u32,
    request: &Cell,
    role: AuthRole,
    signature: &[u8],
) -> anyhow::Result<Cell> {
    anyhow::ensure!(signature.len() == role.signature_bytes(), "wrong PQ signature length");
    let mut tail = None;
    for chunk in signature.chunks(127).rev() {
        let mut b = BuilderData::new();
        let bits = chunk.len().checked_mul(8).ok_or_else(|| anyhow::anyhow!("size overflow"))?;
        b.append_raw(chunk, bits)?;
        if let Some(cell) = tail {
            b.checked_append_reference(cell)?;
        }
        tail = Some(b.into_cell()?);
    }
    let mut b = BuilderData::new();
    b.append_u32(tag)?;
    b.checked_append_reference(request.clone())?;
    b.checked_append_reference(tail.ok_or_else(|| anyhow::anyhow!("empty signature"))?)?;
    b.into_cell()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn byte(value: u8) -> Cell {
        let mut b = BuilderData::new();
        b.append_u8(value).expect("fixture byte");
        b.into_cell().expect("fixture cell")
    }

    fn binding(deadline: u32) -> AuthBinding {
        let mut network = [0; 32];
        network[31] = 123;
        let mut account = [0; 32];
        account[31] = 100;
        let mut module = [0; 32];
        module[31] = 101;
        AuthBinding {
            global_id: 42,
            network,
            account,
            module,
            epoch: 1,
            nonce: 0,
            valid_until: deadline,
        }
    }

    fn execute() -> AuthAction {
        AuthAction::Execute { actions: Cell::default() }
    }

    fn send(previous: Cell, tag: u32, mode: u8) -> Cell {
        let mut b = BuilderData::new();
        b.append_u32(tag).expect("tag");
        b.append_u8(mode).expect("mode");
        b.checked_append_reference(previous).expect("previous");
        b.checked_append_reference(Cell::default()).expect("message fixture");
        b.into_cell().expect("action")
    }

    #[test]
    fn strict_send_modes_before_signing() {
        // Enumerated from the shared wallet's allowed flags: +1, +2, +16,
        // optional 64 OR 128. All other mode bytes must be refused.
        let allowed = [2, 3, 18, 19, 66, 67, 82, 83, 130, 131, 146, 147];
        for mode in 0..=255u8 {
            for role in [AuthRole::Primary, AuthRole::Rescue] {
                let result = AuthRequest::new(
                    binding(1_780_000_600),
                    role,
                    AuthAction::Execute { actions: send(Cell::default(), 0x0ec3c86d, mode) },
                    1_780_000_000,
                );
                assert_eq!(result.is_ok(), allowed.contains(&mode), "role {role:?}, mode {mode}");
            }
        }
    }

    #[test]
    fn strict_action_shape_and_count_before_signing() {
        let mut actions = Cell::default();
        for count in 0..=256 {
            assert_eq!(validate_actions(&actions).is_ok(), count <= 255, "count {count}");
            actions = send(actions, 0x0ec3c86d, 3);
        }
        for tag in [0xad4de08e, 0x36e6b809, 0] {
            assert!(validate_actions(&send(Cell::default(), tag, 3)).is_err(), "tag {tag}");
        }
        let mut tail = BuilderData::new();
        tail.checked_append_reference(Cell::default()).expect("dangling reference");
        assert!(validate_actions(&send(tail.into_cell().expect("tail"), 0x0ec3c86d, 3)).is_err());
        assert!(validate_actions(&byte(1)).is_err());
        for (extra_bit, extra_ref) in [(true, false), (false, true)] {
            let mut malformed = BuilderData::new();
            malformed.append_u32(0x0ec3c86d).expect("tag");
            malformed.append_u8(3).expect("mode");
            if extra_bit {
                malformed.append_bit_zero().expect("extra bit");
            }
            malformed.checked_append_reference(Cell::default()).expect("tail");
            malformed.checked_append_reference(Cell::default()).expect("message");
            if extra_ref {
                malformed.checked_append_reference(Cell::default()).expect("extra ref");
            }
            assert!(validate_actions(&malformed.into_cell().expect("malformed action")).is_err());
        }
        // The check must traverse the entire list, including its oldest action.
        assert!(
            validate_actions(&send(send(Cell::default(), 0x0ec3c86d, 32), 0x0ec3c86d, 3)).is_err()
        );
    }

    #[test]
    fn independent_python_wire_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/v5r2/auth-wire.json"))
                .expect("independent vectors");
        for case in cases.as_array().expect("array") {
            let role = if case["role"] == 1 { AuthRole::Primary } else { AuthRole::Rescue };
            let action = match case["kind"].as_u64().expect("kind") {
                0 => execute(),
                1 => AuthAction::Configure {
                    fee_replacement: if case["replacement"] == true {
                        Some((byte(1), byte(2)))
                    } else {
                        None
                    },
                },
                3 => AuthAction::LockPrimary,
                4 => AuthAction::Migrate {
                    module_init: byte(1),
                    metadata: byte(2),
                    vault_init: byte(3),
                },
                _ => panic!("unknown fixture kind"),
            };
            let req = AuthRequest::new(binding(1_780_000_600), role, action, 1_780_000_000)
                .expect("valid request");
            assert_eq!(hex::encode(req.cell().repr_hash().as_array()), case["request_hash"]);
            assert_eq!(hex::encode(req.digest()), case["digest"]);
            let submit =
                req.encode_submission(&vec![0xa5; role.signature_bytes()]).expect("framing only");
            assert_eq!(hex::encode(submit.repr_hash().as_array()), case["submission_hash"]);
        }
    }

    #[test]
    fn primary_cannot_change_authority() {
        for action in [
            AuthAction::Configure { fee_replacement: None },
            AuthAction::LockPrimary,
            AuthAction::Migrate { module_init: byte(1), metadata: byte(2), vault_init: byte(3) },
        ] {
            let result =
                AuthRequest::new(binding(1_780_000_600), AuthRole::Primary, action, 1_780_000_000);
            assert!(
                result
                    .err()
                    .expect("primary control refused")
                    .to_string()
                    .contains("primary may only execute")
            );
        }
    }

    #[test]
    fn wallet_cannot_be_its_own_module() {
        let mut parties = binding(1_780_000_600);
        parties.module = parties.account;
        let result = AuthRequest::new(parties, AuthRole::Rescue, execute(), 1_780_000_000);
        assert!(
            result
                .err()
                .expect("equal parties refused")
                .to_string()
                .contains("wallet and module must differ")
        );
    }

    #[test]
    fn deadline_and_signature_framing_are_strict() {
        let now = 1_780_000_000;
        for deadline in [now - 1, now, now + 3601] {
            assert!(AuthRequest::new(binding(deadline), AuthRole::Rescue, execute(), now).is_err());
        }
        for ttl in [1, 3600] {
            assert!(AuthRequest::new(binding(now + ttl), AuthRole::Rescue, execute(), now).is_ok());
        }
        for role in [AuthRole::Primary, AuthRole::Rescue] {
            let req = AuthRequest::new(binding(now + 600), role, execute(), now).expect("request");
            for len in [0, 64, role.signature_bytes() - 1, role.signature_bytes() + 1] {
                assert!(req.encode_submission(&vec![0; len]).is_err());
            }
        }
        assert_eq!(AuthRole::Primary.signing_context(), b"TOS-AUTH-V2-ML-DSA-44-v1");
        assert_eq!(AuthRole::Rescue.signing_context(), b"TOS-AUTH-SLH-DSA-SHA2-128S-v1");
    }
}
