use orchard::{bundle::BundleVersion, circuit::OrchardCircuitVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedProfile;

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
}
