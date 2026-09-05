use orchard::{
    bundle::BundleVersion,
    circuit::{OrchardCircuitVersion, VerifyingKey},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyConstructionFailed;

// The key cannot be supplied or replaced by a bundle or FFI caller.
// Full proof/signature verification is not exposed by this prototype yet.
pub struct FixedVerifier {
    key: VerifyingKey,
}

impl FixedVerifier {
    pub fn new() -> Result<Self, KeyConstructionFailed> {
        let key =
            std::panic::catch_unwind(|| VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
                .map_err(|_| KeyConstructionFailed)?;
        Ok(Self { key })
    }

    pub fn check_bundle_profile(&self, bundle: BundleVersion) -> Result<(), UnsupportedProfile> {
        validate_profile(bundle, self.key.circuit_version())
    }
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
