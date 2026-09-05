use orchard::Bundle;
pub mod context;
pub mod decode;
#[cfg(test)]
mod vk_snapshot;
use orchard::{
    bundle::{Authorized, BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, VerifyingKey},
    tree::Anchor,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyConstructionFailed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    Profile,
    Shape(ProofShapeError),
    NonCanonicalAnchor,
    Context(context::ContextError),
    Proof,
    SpendSignature,
    BindingSignature,
}

// The key cannot be supplied or replaced by a bundle or FFI caller.
// This verifies cryptography, not the caller's transaction authorization policy.
pub struct FixedVerifier {
    key: VerifyingKey,
}

impl FixedVerifier {
    // Matching public amounts is not authorization to mint or settle a receipt.
    pub fn verify_in_context(
        &self,
        bundle: &Bundle<Authorized, i64>,
        context: context::PublicContext,
        sighash: &[u8; 32],
        max_actions: usize,
        max_proof_bytes: usize,
    ) -> Result<(), VerificationError> {
        context::check_context(context, *bundle.value_balance(), bundle.flags())
            .map_err(VerificationError::Context)?;
        self.verify_bundle(bundle, sighash, max_actions, max_proof_bytes)
    }

    pub fn new() -> Result<Self, KeyConstructionFailed> {
        let key =
            std::panic::catch_unwind(|| VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
                .map_err(|_| KeyConstructionFailed)?;
        Ok(Self { key })
    }

    pub fn check_bundle_profile(&self, bundle: BundleVersion) -> Result<(), UnsupportedProfile> {
        validate_profile(bundle, self.key.circuit_version())
    }

    pub fn verify_bundle(
        &self,
        bundle: &Bundle<Authorized, i64>,
        sighash: &[u8; 32],
        max_actions: usize,
        max_proof_bytes: usize,
    ) -> Result<(), VerificationError> {
        self.check_bundle_profile(bundle.bundle_version())
            .map_err(|_| VerificationError::Profile)?;
        validate_proof_shape(
            bundle.actions().len(),
            bundle.authorization().proof().as_ref().len(),
            max_actions,
            max_proof_bytes,
        )
        .map_err(VerificationError::Shape)?;
        if !has_canonical_output_only_anchor(bundle.flags(), bundle.anchor()) {
            return Err(VerificationError::NonCanonicalAnchor);
        }
        bundle.verify_proof(&self.key).map_err(|_| VerificationError::Proof)?;
        for action in bundle.actions() {
            action
                .rk()
                .verify(sighash, action.authorization())
                .map_err(|_| VerificationError::SpendSignature)?;
        }
        bundle
            .binding_validating_key()
            .verify(sighash, bundle.authorization().binding_signature())
            .map_err(|_| VerificationError::BindingSignature)?;
        Ok(())
    }
}

// The flag is public; real versus dummy note values are not available here.
fn has_canonical_output_only_anchor(flags: &Flags, anchor: &Anchor) -> bool {
    flags.spends_enabled() || *anchor == Anchor::empty_tree()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofShapeError {
    EmptyOrUnconfigured,
    ActionLimit,
    LengthOverflow,
    ByteLimit,
    NonCanonicalLength,
}

// These limits must come from authenticated configuration before host use.
// No allocation or cryptographic verification is performed here.
pub fn validate_proof_shape(
    actions: usize,
    proof_bytes: usize,
    max_actions: usize,
    max_proof_bytes: usize,
) -> Result<(), ProofShapeError> {
    if actions == 0 || max_actions == 0 || max_proof_bytes == 0 {
        return Err(ProofShapeError::EmptyOrUnconfigured);
    }
    if actions > max_actions {
        return Err(ProofShapeError::ActionLimit);
    }
    let expected = actions
        .checked_mul(2272)
        .and_then(|bytes| bytes.checked_add(2720))
        .ok_or(ProofShapeError::LengthOverflow)?;
    if expected > max_proof_bytes {
        return Err(ProofShapeError::ByteLimit);
    }
    if proof_bytes != expected {
        return Err(ProofShapeError::NonCanonicalLength);
    }
    Ok(())
}

// Prototype gate only; this does not validate a proof or authorize a bundle.
pub fn validate_profile(
    bundle: BundleVersion,
    circuit: OrchardCircuitVersion,
) -> Result<(), UnsupportedProfile> {
    if bundle != BundleVersion::orchard_v2() || circuit != OrchardCircuitVersion::FixedPostNu6_2 {
        return Err(UnsupportedProfile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_real_bundle(bundle: &Bundle<Authorized, i64>) -> Bundle<Authorized, i64> {
        use crate::decode::{decode_bundle, EncodedAction, EncodedBundle};
        let actions: Vec<_> = bundle
            .actions()
            .iter()
            .map(|action| EncodedAction {
                cv_net: action.cv_net().to_bytes(),
                nullifier: action.nullifier().to_bytes(),
                rk: action.rk().into(),
                cmx: action.cmx().to_bytes(),
                epk: action.encrypted_note().epk_bytes,
                enc_ciphertext: action.encrypted_note().enc_ciphertext,
                out_ciphertext: action.encrypted_note().out_ciphertext,
                spend_signature: action.authorization().into(),
            })
            .collect();
        decode_bundle(
            &EncodedBundle {
                profile: bundle.bundle_version(),
                flags: bundle.flag_byte(),
                value_balance: *bundle.value_balance(),
                anchor: bundle.anchor().to_bytes(),
                actions: &actions,
                proof: bundle.authorization().proof().as_ref(),
                binding_signature: bundle.authorization().binding_signature().into(),
            },
            2,
            7264,
        )
        .expect("decode real bundle")
    }

    #[test]
    fn real_bundle_requires_proof_and_signatures() {
        use incrementalmerkletree::Hashable;
        use orchard::{
            builder::{Builder, BundleType},
            bundle::Flags,
            circuit::ProvingKey,
            keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
            tree::{Anchor, MerkleHashOrchard, MerklePath},
            value::NoteValue,
            Proof,
        };
        let mut rng = rand::rngs::OsRng;
        let sk = SpendingKey::from_bytes([0; 32]).expect("test spending key");
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .expect("test builder");
        builder
            .add_output(None, recipient, NoteValue::from_raw(5000), [0; 512])
            .expect("test output");
        let (unsigned, metadata) =
            builder.build::<i64>(&mut rng).expect("build").expect("nonempty");
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        let digest = [42; 32];
        let bundle = unsigned
            .create_proof(&pk, &mut rng)
            .expect("proof")
            .apply_signatures(&mut rng, digest, &[])
            .expect("signatures");
        let verifier = FixedVerifier::new().expect("fixed key");
        let bundle = decode_real_bundle(&bundle);
        assert_eq!(verifier.verify_bundle(&bundle, &digest, 2, 7264), Ok(()));
        use context::{ContextError, PublicContext};
        for context in [
            PublicContext::ShieldClaim { amount: 5000 },
            PublicContext::WithdrawalRefund { amount: 5000 },
            PublicContext::Genesis { amount: 5000 },
            PublicContext::PrivateFeeDistribution { amount: 5000 },
        ] {
            assert_eq!(verifier.verify_in_context(&bundle, context, &digest, 2, 7264), Ok(()));
        }
        assert_eq!(
            verifier.verify_in_context(
                &bundle,
                PublicContext::ShieldClaim { amount: 5001 },
                &digest,
                2,
                7264
            ),
            Err(VerificationError::Context(ContextError::ValueBalance))
        );

        // Recover an actual nonzero output and spend it from a single-leaf tree.
        // This uses the dependency's test encryption, not the required hybrid profile.
        let fvk = FullViewingKey::from(&sk);
        let (note, _, _) = bundle
            .decrypt_output_with_key(
                metadata.output_action_index(0).expect("real output index"),
                &fvk.to_ivk(Scope::External),
            )
            .expect("recover real note");
        assert_eq!(note.value(), NoteValue::from_raw(5000));
        let path = MerklePath::from_parts(
            0,
            std::array::from_fn(|level| {
                MerkleHashOrchard::empty_root(u8::try_from(level).expect("tree level").into())
            }),
        );
        let anchor = path.root(note.commitment().into());
        let mut spender = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_v2().default_flags(),
            anchor,
        )
        .expect("spend builder");
        spender.add_spend(fvk, note, path).expect("real spend");
        spender
            .add_output(None, recipient, NoteValue::from_raw(4900), [0; 512])
            .expect("change output");
        let (unsigned_spend, spend_metadata) =
            spender.build::<i64>(&mut rng).expect("spend build").expect("nonempty spend");
        assert_eq!(*unsigned_spend.value_balance(), 100);
        let real_spend_index = spend_metadata.spend_action_index(0).expect("real spend index");
        let spent = unsigned_spend
            .create_proof(&pk, &mut rng)
            .expect("spend proof")
            .apply_signatures(&mut rng, digest, &[SpendAuthorizingKey::from(&sk)])
            .expect("real spend authorization");
        assert_eq!(verifier.verify_bundle(&spent, &digest, 2, 7264), Ok(()));
        let spent = decode_real_bundle(&spent);
        assert_eq!(verifier.verify_bundle(&spent, &digest, 2, 7264), Ok(()));
        assert_eq!(
            verifier.verify_in_context(
                &spent,
                PublicContext::Transfer { fee: 100 },
                &digest,
                2,
                7264
            ),
            Ok(())
        );
        assert_eq!(
            verifier.verify_in_context(
                &spent,
                PublicContext::Unshield { amount: 80, fee: 20 },
                &digest,
                2,
                7264
            ),
            Ok(())
        );
        assert_eq!(
            verifier.verify_in_context(
                &spent,
                PublicContext::Transfer { fee: 101 },
                &digest,
                2,
                7264
            ),
            Err(VerificationError::Context(ContextError::ValueBalance))
        );
        let wrong_balance = spent
            .clone()
            .try_map_value_balance(|_| Ok::<i64, std::convert::Infallible>(101))
            .expect("typed balance change");
        assert_eq!(
            verifier.verify_bundle(&wrong_balance, &digest, 2, 7264),
            Err(VerificationError::BindingSignature)
        );
        let bad_real_spend = spent.map_authorization(
            &mut 0usize,
            |index, _, sig| {
                let result = if *index == real_spend_index { [0; 64].into() } else { sig };
                *index = index.checked_add(1).expect("action index");
                result
            },
            |_, auth| auth,
        );
        assert_eq!(
            verifier.verify_bundle(&bad_real_spend, &digest, 2, 7264),
            Err(VerificationError::SpendSignature)
        );
        assert!(verifier.verify_bundle(&bundle, &[43; 32], 2, 7264).is_err());
        let bad_spend =
            bundle.clone().map_authorization(&mut (), |_, _, _| [0; 64].into(), |_, auth| auth);
        assert_eq!(
            verifier.verify_bundle(&bad_spend, &digest, 2, 7264),
            Err(VerificationError::SpendSignature)
        );
        let bad_proof = bundle.clone().map_authorization(
            &mut (),
            |_, _, sig| sig,
            |_, auth| {
                let mut bytes = auth.proof().as_ref().to_vec();
                bytes[0] ^= 1;
                Authorized::from_parts(Proof::new(bytes), auth.binding_signature().clone())
            },
        );
        assert_eq!(
            verifier.verify_bundle(&bad_proof, &digest, 2, 7264),
            Err(VerificationError::Proof)
        );
        assert_eq!(
            verifier.verify_in_context(
                &bad_proof,
                PublicContext::ShieldClaim { amount: 5000 },
                &digest,
                2,
                7264
            ),
            Err(VerificationError::Proof)
        );
        let bad_binding = bundle.map_authorization(
            &mut (),
            |_, _, sig| sig,
            |_, auth| Authorized::from_parts(auth.proof().clone(), [0; 64].into()),
        );
        assert_eq!(
            verifier.verify_bundle(&bad_binding, &digest, 2, 7264),
            Err(VerificationError::BindingSignature)
        );
    }

    #[test]
    fn valid_proof_does_not_authorize_noncanonical_output_only_anchor() {
        use orchard::{
            builder::{Builder, BundleType},
            circuit::ProvingKey,
            keys::{FullViewingKey, Scope, SpendingKey},
            value::NoteValue,
        };
        let mut rng = rand::rngs::OsRng;
        let sk = SpendingKey::from_bytes([0; 32]).expect("test spending key");
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        let wrong_anchor = Option::<Anchor>::from(Anchor::from_bytes([0; 32])).expect("field zero");
        assert_ne!(wrong_anchor, Anchor::empty_tree());
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            wrong_anchor,
        )
        .expect("output-only builder");
        builder.add_output(None, recipient, NoteValue::from_raw(5000), [0; 512]).expect("output");
        let (unsigned, _) = builder.build::<i64>(&mut rng).expect("build").expect("nonempty");
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        let digest = [42; 32];
        let bundle = unsigned
            .create_proof(&pk, &mut rng)
            .expect("proof")
            .apply_signatures(&mut rng, digest, &[])
            .expect("signatures");
        let verifier = FixedVerifier::new().expect("fixed key");
        assert_eq!(*bundle.anchor(), wrong_anchor);
        assert!(bundle.verify_proof(&verifier.key).is_ok());
        for action in bundle.actions() {
            assert!(action.rk().verify(&digest, action.authorization()).is_ok());
        }
        assert!(bundle
            .binding_validating_key()
            .verify(&digest, bundle.authorization().binding_signature())
            .is_ok());
        assert_eq!(
            verifier.verify_bundle(&bundle, &digest, 2, 7264),
            Err(VerificationError::NonCanonicalAnchor)
        );
    }

    #[test]
    fn constructed_key_is_bound_to_fixed_profile() {
        let verifier = match FixedVerifier::new() {
            Ok(verifier) => verifier,
            Err(error) => panic!("key construction failed: {error:?}"),
        };
        assert_eq!(verifier.key.circuit_version(), OrchardCircuitVersion::FixedPostNu6_2);
        assert_eq!(verifier.check_bundle_profile(BundleVersion::orchard_v2()), Ok(()));
        for version in [
            BundleVersion::orchard_insecure_v1(),
            BundleVersion::orchard_v3(),
            BundleVersion::ironwood_v3(),
        ] {
            assert_eq!(verifier.check_bundle_profile(version), Err(UnsupportedProfile));
        }
    }

    #[test]
    fn profile_requires_both_fixed_selectors() {
        let bundles = [
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_insecure_v1(),
            BundleVersion::orchard_v3(),
            BundleVersion::ironwood_v3(),
        ];
        let circuits = [
            OrchardCircuitVersion::FixedPostNu6_2,
            OrchardCircuitVersion::InsecurePreNu6_2,
            OrchardCircuitVersion::PostNu6_3,
        ];
        for (b, bundle) in bundles.into_iter().enumerate() {
            for (c, circuit) in circuits.into_iter().enumerate() {
                assert_eq!(validate_profile(bundle, circuit).is_ok(), b == 0 && c == 0);
            }
        }
    }

    #[test]
    fn proof_shape_matches_pinned_circuit_sizes() {
        assert_eq!(orchard::Proof::expected_proof_size(1), 4992);
        assert_eq!(orchard::Proof::expected_proof_size(2), 7264);
        for actions in 1..=32 {
            let size = orchard::Proof::expected_proof_size(actions);
            assert_eq!(validate_proof_shape(actions, size, 32, size), Ok(()));
            assert_eq!(
                validate_proof_shape(actions, size - 1, 32, size),
                Err(ProofShapeError::NonCanonicalLength)
            );
            assert_eq!(
                validate_proof_shape(actions, size + 1, 32, size + 1),
                Err(ProofShapeError::NonCanonicalLength)
            );
        }
    }

    #[test]
    fn proof_shape_rejects_resource_and_arithmetic_boundaries() {
        assert_eq!(
            validate_proof_shape(0, 2720, 1, 4992),
            Err(ProofShapeError::EmptyOrUnconfigured)
        );
        assert_eq!(
            validate_proof_shape(1, 4992, 0, 4992),
            Err(ProofShapeError::EmptyOrUnconfigured)
        );
        assert_eq!(validate_proof_shape(1, 4992, 1, 0), Err(ProofShapeError::EmptyOrUnconfigured));
        assert_eq!(validate_proof_shape(2, 7264, 1, 7264), Err(ProofShapeError::ActionLimit));
        assert_eq!(validate_proof_shape(1, 4992, 1, 4991), Err(ProofShapeError::ByteLimit));
        assert_eq!(
            validate_proof_shape(usize::MAX, 0, usize::MAX, usize::MAX),
            Err(ProofShapeError::LengthOverflow)
        );
        let addition_overflow = usize::MAX / 2272;
        for actions in [addition_overflow, addition_overflow + 1] {
            let wrapped_size = actions.wrapping_mul(2272).wrapping_add(2720);
            assert_eq!(
                validate_proof_shape(actions, wrapped_size, usize::MAX, usize::MAX),
                Err(ProofShapeError::LengthOverflow)
            );
        }
    }
}
