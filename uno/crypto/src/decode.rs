//! Fixed-profile primitive decoding, not the outer transaction Cell codec.
use nonempty::NonEmpty;
use orchard::{
    bundle::{Authorized, BundleVersion, Flags},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    primitives::redpallas::{SpendAuth, VerificationKey},
    tree::Anchor,
    value::ValueCommitment,
    Action, Bundle, Proof,
};

use crate::{has_canonical_output_only_anchor, validate_proof_shape, ProofShapeError};

#[derive(Clone)]
pub struct EncodedAction {
    pub cv_net: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub epk: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub spend_signature: [u8; 64],
}

pub struct EncodedBundle<'a> {
    pub profile: BundleVersion,
    pub flags: u8,
    pub value_balance: i64,
    pub anchor: [u8; 32],
    pub actions: &'a [EncodedAction],
    pub proof: &'a [u8],
    pub binding_signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Profile,
    Shape(ProofShapeError),
    Flags,
    ValueBalance,
    Anchor,
    NonCanonicalAnchor,
    ValueCommitment,
    Nullifier,
    RandomizedKey,
    NoteCommitment,
    Action,
    Allocation,
    Bundle,
}

// Borrow caller-owned bytes. Bound allocations before copying actions or proof.
// Signature bytes are preserved; their canonicality/equations are verified later.
pub fn decode_bundle(
    encoded: &EncodedBundle<'_>,
    max_actions: usize,
    max_proof_bytes: usize,
) -> Result<Bundle<Authorized, i64>, DecodeError> {
    if encoded.profile != BundleVersion::orchard_v2() {
        return Err(DecodeError::Profile);
    }
    validate_proof_shape(encoded.actions.len(), encoded.proof.len(), max_actions, max_proof_bytes)
        .map_err(DecodeError::Shape)?;
    let flags = Flags::from_byte(encoded.flags, encoded.profile).ok_or(DecodeError::Flags)?;
    if encoded.value_balance == i64::MIN {
        return Err(DecodeError::ValueBalance);
    }
    let anchor =
        Option::<Anchor>::from(Anchor::from_bytes(encoded.anchor)).ok_or(DecodeError::Anchor)?;
    if !has_canonical_output_only_anchor(&flags, &anchor) {
        return Err(DecodeError::NonCanonicalAnchor);
    }
    let mut actions = Vec::new();
    actions.try_reserve_exact(encoded.actions.len()).map_err(|_| DecodeError::Allocation)?;
    for raw in encoded.actions {
        let cv = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&raw.cv_net))
            .ok_or(DecodeError::ValueCommitment)?;
        let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&raw.nullifier))
            .ok_or(DecodeError::Nullifier)?;
        let rk = VerificationKey::<SpendAuth>::try_from(raw.rk)
            .map_err(|_| DecodeError::RandomizedKey)?;
        let cmx =
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&raw.cmx))
                .ok_or(DecodeError::NoteCommitment)?;
        let action = Action::from_parts(
            nf,
            rk,
            cmx,
            TransmittedNoteCiphertext {
                epk_bytes: raw.epk,
                enc_ciphertext: raw.enc_ciphertext,
                out_ciphertext: raw.out_ciphertext,
            },
            cv,
            raw.spend_signature.into(),
        )
        .map_err(|_| DecodeError::Action)?;
        actions.push(action);
    }
    let actions = NonEmpty::from_vec(actions).ok_or(DecodeError::Bundle)?;
    let mut proof = Vec::new();
    proof.try_reserve_exact(encoded.proof.len()).map_err(|_| DecodeError::Allocation)?;
    proof.extend_from_slice(encoded.proof);
    Bundle::try_from_parts(
        actions,
        flags,
        encoded.value_balance,
        anchor,
        Authorized::from_parts(Proof::new(proof), encoded.binding_signature.into()),
        encoded.profile,
    )
    .map_err(|_| DecodeError::Bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::primitives::redpallas::SigningKey;

    fn action() -> EncodedAction {
        let key = SigningKey::<SpendAuth>::try_from([1; 32]).expect("fixture key");
        let point: [u8; 32] = VerificationKey::from(&key).into();
        EncodedAction {
            cv_net: point,
            nullifier: [0; 32],
            rk: point,
            cmx: [0; 32],
            epk: point,
            enc_ciphertext: [17; 580],
            out_ciphertext: [23; 80],
            spend_signature: [31; 64],
        }
    }

    fn bundle<'a>(actions: &'a [EncodedAction], proof: &'a [u8]) -> EncodedBundle<'a> {
        EncodedBundle {
            profile: BundleVersion::orchard_v2(),
            flags: 3,
            value_balance: 0,
            anchor: Anchor::empty_tree().to_bytes(),
            actions,
            proof,
            binding_signature: [47; 64],
        }
    }

    #[test]
    fn decoding_preserves_primitive_bytes_without_authorizing_them() {
        let actions = [action()];
        let proof = [59; 4992];
        let raw = bundle(&actions, &proof);
        let decoded = decode_bundle(&raw, 1, 4992).expect("structural fixture");
        let out = &decoded.actions()[0];
        assert_eq!(out.cv_net().to_bytes(), actions[0].cv_net);
        assert_eq!(out.nullifier().to_bytes(), actions[0].nullifier);
        assert_eq!(<[u8; 32]>::from(out.rk()), actions[0].rk);
        assert_eq!(out.cmx().to_bytes(), actions[0].cmx);
        assert_eq!(out.encrypted_note().epk_bytes, actions[0].epk);
        assert_eq!(out.encrypted_note().enc_ciphertext, actions[0].enc_ciphertext);
        assert_eq!(out.encrypted_note().out_ciphertext, actions[0].out_ciphertext);
        assert_eq!(<[u8; 64]>::from(out.authorization()), actions[0].spend_signature);
        assert_eq!(decoded.authorization().proof().as_ref(), proof);
        assert_eq!(
            <[u8; 64]>::from(decoded.authorization().binding_signature()),
            raw.binding_signature
        );
        assert_eq!(decoded.anchor().to_bytes(), raw.anchor);
        assert_eq!(decoded.flag_byte(), raw.flags);
        for value in [-i64::MAX, 0, i64::MAX] {
            let raw = EncodedBundle { value_balance: value, ..bundle(&actions, &proof) };
            assert_eq!(
                *decode_bundle(&raw, 1, 4992).expect("symmetric balance").value_balance(),
                value
            );
        }
    }

    #[test]
    fn decoding_rejects_header_and_resource_errors() {
        let actions = [action()];
        let proof = [59; 4992];
        let mut raw = bundle(&actions, &proof);
        assert!(decode_bundle(&raw, 1, 4992).is_ok());
        for profile in [
            BundleVersion::orchard_insecure_v1(),
            BundleVersion::orchard_v3(),
            BundleVersion::ironwood_v3(),
        ] {
            raw.profile = profile;
            assert_eq!(decode_bundle(&raw, 1, 4992).err(), Some(DecodeError::Profile));
        }
        raw.profile = BundleVersion::orchard_v2();
        for flags in 4..=255 {
            raw.flags = flags;
            assert_eq!(decode_bundle(&raw, 1, 4992).err(), Some(DecodeError::Flags));
        }
        raw.flags = 3;
        raw.value_balance = i64::MIN;
        assert_eq!(decode_bundle(&raw, 1, 4992).err(), Some(DecodeError::ValueBalance));
        raw.value_balance = 0;
        raw.anchor = [255; 32];
        assert_eq!(decode_bundle(&raw, 1, 4992).err(), Some(DecodeError::Anchor));
        raw.anchor = Anchor::empty_tree().to_bytes();
        assert_eq!(
            decode_bundle(&raw, 1, 4991).err(),
            Some(DecodeError::Shape(ProofShapeError::ByteLimit))
        );
        let pair = [action(), action()];
        let pair_proof = [59; 7264];
        let pair_raw = bundle(&pair, &pair_proof);
        assert_eq!(
            decode_bundle(&pair_raw, 1, 7264).err(),
            Some(DecodeError::Shape(ProofShapeError::ActionLimit))
        );
        assert!(decode_bundle(&pair_raw, 2, 7264).is_ok());
    }

    #[test]
    fn disabled_spends_require_empty_tree_anchor() {
        let actions = [action()];
        let proof = [59; 4992];
        let mut raw = bundle(&actions, &proof);
        for flags in 0..=3 {
            raw.flags = flags;
            raw.anchor = Anchor::empty_tree().to_bytes();
            assert!(decode_bundle(&raw, 1, 4992).is_ok());
            raw.anchor = [0; 32];
            if flags & 1 == 0 {
                assert_eq!(
                    decode_bundle(&raw, 1, 4992).err(),
                    Some(DecodeError::NonCanonicalAnchor)
                );
            } else {
                assert!(decode_bundle(&raw, 1, 4992).is_ok());
            }
        }
    }

    #[test]
    fn decoding_rejects_noncanonical_action_fields() {
        let proof = [59; 4992];
        for field in 0..7 {
            let mut raw_action = action();
            let error = match field {
                0 => {
                    raw_action.cv_net = [255; 32];
                    DecodeError::ValueCommitment
                }
                1 => {
                    raw_action.nullifier = [255; 32];
                    DecodeError::Nullifier
                }
                2 => {
                    raw_action.rk = [255; 32];
                    DecodeError::RandomizedKey
                }
                3 => {
                    raw_action.cmx = [255; 32];
                    DecodeError::NoteCommitment
                }
                4 => {
                    raw_action.rk = [0; 32];
                    DecodeError::Action
                }
                5 => {
                    raw_action.epk = [0; 32];
                    DecodeError::Action
                }
                _ => {
                    raw_action.epk = [255; 32];
                    DecodeError::Action
                }
            };
            let actions = [raw_action];
            assert_eq!(
                decode_bundle(&bundle(&actions, &proof), 1, 4992).err(),
                Some(error),
                "field {field}"
            );
        }
    }
}
