// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Fee wire encoding, not a signer, reservation or trusted-state verifier.
//!
//! Obtain the paired vault/config and time from verified current state. Before
//! signing, reserve the leaf durably through FeeJournal; retries use cached
//! signature bytes. This layer checks framing, not any cryptographic signature,
//! current balance/fees, full inner-message policy or immutable party pairing.
use crate::lms_fee_schedule::{LEAF_COUNT, LEAVES_PER_SLOT, SLOT_SECONDS};
use chain_block::{BuilderData, Cell, CellType, Coins, IBitstring, Serializable, SliceData};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeClass {
    RescueAuth,
    Pop,
    Prepare,
}

pub struct FeePayload {
    class: FeeClass,
    cell: Cell,
}
impl FeePayload {
    /// Import a complete signed SUB3/PPS3/FPR3 envelope. Structural checks only;
    /// the module/wallet still validate inner contents and PQ signatures.
    pub fn from_submission(class: FeeClass, cell: Cell) -> anyhow::Result<Self> {
        anyhow::ensure!(
            cell.cell_type() == CellType::Ordinary && cell.level() == 0,
            "ordinary fee payload required"
        );
        let mut s = SliceData::load_cell(cell.clone())?;
        anyhow::ensure!(
            s.remaining_bits() == 32 && s.remaining_references() == 2,
            "fee payload shape"
        );
        let (tag, request_tag, bits, refs) = match class {
            FeeClass::RescueAuth => (0x53554233, 0x41553252, 1019, 1),
            FeeClass::Pop => (0x50505333, 0x504f5033, 616, 2),
            FeeClass::Prepare => (0x46505233, 0x50525033, 875, 1),
        };
        anyhow::ensure!(s.get_next_u32()? == tag, "fee class/submission mismatch");
        let request = s.checked_drain_reference()?;
        anyhow::ensure!(
            request.cell_type() == CellType::Ordinary && request.level() == 0,
            "ordinary fee request required"
        );
        let mut r = SliceData::load_cell(request)?;
        anyhow::ensure!(
            r.remaining_bits() == bits && r.remaining_references() == refs,
            "fee request shape"
        );
        anyhow::ensure!(r.get_next_u32()? == request_tag, "fee request constructor");
        if class == FeeClass::RescueAuth {
            r.move_by(811)?;
            anyhow::ensure!(r.get_next_byte()? == 2, "fee vault cannot fund primary AUTH");
        }
        Ok(Self { class, cell })
    }
}

#[derive(Clone, Copy)]
pub struct FeeBinding {
    pub vault: [u8; 32],
    pub config_hash: [u8; 32],
    pub epoch0: u32,
    pub leaf: u32,
    pub valid_until: u32,
    pub value: u128,
}

#[derive(Clone)]
pub struct FeeIntent {
    cell: Cell,
    digest: [u8; 32],
    binding: FeeBinding,
}
impl FeeIntent {
    /// Construct a new signing intent using only a current-slot leaf. The
    /// previous-slot delivery allowance is not permission for new signatures.
    /// This does not allocate a leaf; FeeJournal must reserve this exact digest.
    pub fn new(binding: FeeBinding, payload: FeePayload, proven_time: u32) -> anyhow::Result<Self> {
        let ttl = binding
            .valid_until
            .checked_sub(proven_time)
            .ok_or_else(|| anyhow::anyhow!("expired fee deadline"))?;
        anyhow::ensure!((1..=SLOT_SECONDS).contains(&ttl), "fee TTL must be 1..=3600 seconds");
        anyhow::ensure!(binding.leaf < LEAF_COUNT, "fee tree exhausted");
        let elapsed = proven_time
            .checked_sub(binding.epoch0)
            .ok_or_else(|| anyhow::anyhow!("before fee epoch"))?;
        anyhow::ensure!(
            binding.leaf / LEAVES_PER_SLOT == elapsed / SLOT_SECONDS,
            "new fee signature requires current slot"
        );
        anyhow::ensure!(binding.value > 0, "fee value must be positive");
        let mut b = BuilderData::new();
        b.append_u32(0x46454534)?;
        b.append_raw(b"TOS-RESCUE-FEE-v1", 136)?;
        b.append_u8(match payload.class {
            FeeClass::RescueAuth => 1,
            FeeClass::Pop => 2,
            FeeClass::Prepare => 3,
        })?;
        b.append_raw(&[0x80, 0], 11)?;
        b.append_u256(&binding.vault)?;
        b.append_u256(&binding.config_hash)?;
        b.append_u32(binding.leaf)?;
        b.append_u32(binding.valid_until)?;
        binding.value.to_string().parse::<Coins>()?.write_to(&mut b)?;
        b.checked_append_reference(payload.cell)?;
        let cell = b.into_cell()?;
        let digest = *cell.repr_hash().as_array();
        Ok(Self { cell, digest, binding })
    }
    pub(crate) fn binding(&self) -> &FeeBinding {
        &self.binding
    }
    pub fn cell(&self) -> &Cell {
        &self.cell
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn leaf(&self) -> u32 {
        self.binding.leaf
    }
    /// Encode the external body from verified cached signature bytes. This only
    /// checks fixed HSS L1/H20/W4 framing and the reserved leaf, not validity.
    /// Recheck current admission/expiry independently before broadcasting.
    pub fn encode_external(&self, signature: &[u8]) -> anyhow::Result<Cell> {
        anyhow::ensure!(signature.len() == 2832, "fee signature length");
        anyhow::ensure!(
            signature[..4] == 0u32.to_be_bytes()
                && signature[4..8] == self.binding.leaf.to_be_bytes()
                && signature[8..12] == 3u32.to_be_bytes()
                && signature[2188..2192] == 8u32.to_be_bytes(),
            "fee signature profile/leaf mismatch"
        );
        let mut tail = None;
        for chunk in signature.chunks(127).rev() {
            let mut b = BuilderData::new();
            b.append_raw(
                chunk,
                chunk.len().checked_mul(8).ok_or_else(|| anyhow::anyhow!("size overflow"))?,
            )?;
            if let Some(cell) = tail {
                b.checked_append_reference(cell)?;
            }
            tail = Some(b.into_cell()?);
        }
        let mut b = BuilderData::new();
        b.checked_append_reference(self.cell.clone())?;
        b.checked_append_reference(tail.ok_or_else(|| anyhow::anyhow!("empty signature"))?)?;
        b.into_cell()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        wallet_v5r2::{AuthAction, AuthBinding, AuthRequest, AuthRole},
        wallet_v5r2_pop::{PopBinding, PopRequest, RescuePolicy},
        wallet_v5r2_prepare::{PreparationBinding, PreparationPlan, PreparationRequest},
    };
    fn hash(v: u8) -> [u8; 32] {
        let mut h = [0; 32];
        h[31] = v;
        h
    }
    fn byte(v: u8) -> Cell {
        let mut b = BuilderData::new();
        b.append_u8(v).expect("byte");
        b.into_cell().expect("cell")
    }
    fn submission(class: FeeClass, role: AuthRole) -> Cell {
        let signature = vec![0xa5; role.signature_bytes()];
        match class {
            FeeClass::RescueAuth => AuthRequest::new(
                AuthBinding {
                    global_id: 42,
                    network: hash(123),
                    account: hash(100),
                    module: hash(101),
                    epoch: 1,
                    nonce: 0,
                    valid_until: 1_780_000_600,
                },
                role,
                AuthAction::Execute { actions: Cell::default() },
                1_780_000_000,
            )
            .expect("auth")
            .encode_submission(&signature)
            .expect("submission"),
            FeeClass::Pop => PopRequest::new(
                PopBinding {
                    global_id: 42,
                    network: hash(123),
                    account: hash(100),
                    module: hash(101),
                    challenge: hash(99),
                    valid_until: 1_780_000_600,
                },
                role,
                RescuePolicy::Required,
                hash(111),
                hash(222),
                1_780_000_000,
            )
            .expect("pop")
            .encode_submission(&signature)
            .expect("submission"),
            FeeClass::Prepare => PreparationRequest::new(
                PreparationBinding {
                    global_id: 42,
                    network: hash(123),
                    wallet: hash(100),
                    source_module: hash(101),
                    valid_until: 1_780_000_600,
                },
                PreparationPlan {
                    module_amount: 10_000_000_000,
                    vault_amount: 20_000_000_000,
                    module_init: byte(1),
                    metadata: byte(2),
                    vault_init: byte(3),
                },
                1_780_000_000,
            )
            .expect("prepare")
            .encode_submission(&signature)
            .expect("submission"),
        }
    }
    fn payload() -> FeePayload {
        FeePayload::from_submission(
            FeeClass::RescueAuth,
            submission(FeeClass::RescueAuth, AuthRole::Rescue),
        )
        .expect("payload")
    }
    fn binding() -> FeeBinding {
        FeeBinding {
            vault: hash(103),
            config_hash: hash(104),
            epoch0: 1_779_992_790,
            leaf: 8,
            valid_until: 1_780_000_600,
            value: 5_000_000_000,
        }
    }
    fn signature() -> Vec<u8> {
        let mut s = vec![0xa5; 2832];
        for (offset, word) in [(0, 0u32), (4, 8), (8, 3), (2188, 8)] {
            s[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
        }
        s
    }
    #[test]
    fn independent_fee_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/v5r2/fee-wire.json"))
                .expect("vectors");
        for c in cases.as_array().expect("array") {
            let class = match c["kind"].as_u64().expect("kind") {
                1 => FeeClass::RescueAuth,
                2 => FeeClass::Pop,
                3 => FeeClass::Prepare,
                _ => panic!("kind"),
            };
            let mut b = binding();
            b.value = c["value"].as_str().expect("value").parse().expect("number");
            let p = FeePayload::from_submission(class, submission(class, AuthRole::Rescue))
                .expect("payload");
            let intent = FeeIntent::new(b, p, 1_780_000_000).expect("intent");
            assert_eq!(hex::encode(intent.digest()), c["intent_hash"]);
            assert_eq!(
                hex::encode(
                    intent.encode_external(&signature()).expect("external").repr_hash().as_array()
                ),
                c["external_hash"]
            );
        }
    }
    #[test]
    fn primary_auth_and_class_mismatch_refused() {
        assert!(
            FeePayload::from_submission(
                FeeClass::RescueAuth,
                submission(FeeClass::RescueAuth, AuthRole::Primary)
            )
            .is_err()
        );
        for class in [FeeClass::Pop, FeeClass::Prepare] {
            assert!(
                FeePayload::from_submission(
                    class,
                    submission(FeeClass::RescueAuth, AuthRole::Rescue)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn exhausted_tree_even_at_matching_slot() {
        let mut b = binding();
        b.leaf = LEAF_COUNT;
        let now = b
            .epoch0
            .checked_add((LEAF_COUNT / LEAVES_PER_SLOT).checked_mul(SLOT_SECONDS).expect("slot"))
            .expect("time");
        b.valid_until = now.checked_add(600).expect("deadline");
        assert!(FeeIntent::new(b, payload(), now).is_err());
    }
    #[test]
    fn structural_mismatches_refused() {
        let pop = submission(FeeClass::Pop, AuthRole::Rescue);
        let mut p = SliceData::load_cell(pop.clone()).expect("slice");
        p.get_next_u32().expect("tag");
        let request = p.checked_drain_reference().expect("request");
        let sig = p.checked_drain_reference().expect("signature");
        let mut wrong_tag = BuilderData::new();
        wrong_tag.append_u32(0x53554233).expect("tag");
        wrong_tag.checked_append_reference(request.clone()).expect("ref");
        wrong_tag.checked_append_reference(sig.clone()).expect("ref");
        assert!(
            FeePayload::from_submission(FeeClass::Pop, wrong_tag.into_cell().expect("cell"))
                .is_err()
        );
        let mut extra = BuilderData::from_cell(&pop).expect("builder");
        extra.append_bit_one().expect("extra bit");
        assert!(
            FeePayload::from_submission(FeeClass::Pop, extra.into_cell().expect("cell")).is_err()
        );
        let mut extra_request = BuilderData::from_cell(&request).expect("builder");
        extra_request.append_bit_one().expect("extra bit");
        let mut body = BuilderData::new();
        body.append_u32(0x50505333).expect("tag");
        body.checked_append_reference(extra_request.into_cell().expect("cell")).expect("ref");
        body.checked_append_reference(sig).expect("ref");
        assert!(
            FeePayload::from_submission(FeeClass::Pop, body.into_cell().expect("cell")).is_err()
        );
    }
    #[test]
    fn trailing_signature_bytes_refused() {
        let intent = FeeIntent::new(binding(), payload(), 1_780_000_000).expect("intent");
        let mut extra = signature();
        extra.push(0);
        assert!(intent.encode_external(&extra).is_err());
    }

    #[test]
    fn leaf_deadline_value_and_framing_boundaries() {
        let now = 1_780_000_000;
        for leaf in [0, 4, 7, 12, LEAF_COUNT, u32::MAX] {
            let mut b = binding();
            b.leaf = leaf;
            assert!(FeeIntent::new(b, payload(), now).is_err());
        }
        for leaf in 8..12 {
            let mut b = binding();
            b.leaf = leaf;
            assert!(FeeIntent::new(b, payload(), now).is_ok());
        }
        for deadline in [now - 1, now, now + 3601] {
            let mut b = binding();
            b.valid_until = deadline;
            assert!(FeeIntent::new(b, payload(), now).is_err());
        }
        for value in [0, 1u128 << 120, u128::MAX] {
            let mut b = binding();
            b.value = value;
            assert!(FeeIntent::new(b, payload(), now).is_err());
        }
        let mut b = binding();
        b.epoch0 = now + 1;
        assert!(FeeIntent::new(b, payload(), now).is_err());
        let intent = FeeIntent::new(binding(), payload(), now).expect("intent");
        for offset in [0, 4, 8, 2188] {
            let mut sig = signature();
            sig[offset] ^= 1;
            assert!(intent.encode_external(&sig).is_err());
        }
        for len in [64, 2420, 2831, 2833] {
            assert!(intent.encode_external(&vec![0; len]).is_err());
        }
    }
}
