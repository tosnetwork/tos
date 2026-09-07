//! The two range equations are checked independently, without verifier entropy.
use super::*;

impl RangeProof {
    /// Verify the original transcript with independent inner-product and polynomial checks.
    /// The caller must bound the number of commitments before constructing generators.
    pub fn verify_independent(
        &self, bp: &BulletproofGens, pc: &PedersenGens, t: &mut Transcript,
        values: &[CompressedRistretto], n: usize,
    ) -> Result<(), ProofError> {
        let m = values.len();
        let nm = n.checked_mul(m).ok_or(ProofError::InvalidBitsize)?;
        if ![8, 16, 32, 64].contains(&n) || !m.is_power_of_two() {
            return Err(ProofError::InvalidBitsize);
        }
        if bp.gens_capacity < n || bp.party_capacity < m {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        t.rangeproof_domain_sep(n as u64, m as u64);
        for value in values { t.append_point(b"V", value); }
        t.validate_and_append_point(b"A", &self.A)?;
        t.validate_and_append_point(b"S", &self.S)?;
        let y = t.challenge_scalar(b"y");
        let z = t.challenge_scalar(b"z");
        t.validate_and_append_point(b"T_1", &self.T_1)?;
        t.validate_and_append_point(b"T_2", &self.T_2)?;
        let x = t.challenge_scalar(b"x");
        t.append_scalar(b"t_x", &self.t_x);
        t.append_scalar(b"t_x_blinding", &self.t_x_blinding);
        t.append_scalar(b"e_blinding", &self.e_blinding);
        let w = t.challenge_scalar(b"w");
        let (xs, xis, s) = self.ipp_proof.verification_scalars(nm, t)?;
        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;
        t.append_scalar(b"ipp_a", &a);
        t.append_scalar(b"ipp_b", &b);
        // Preserve the challenge event, but do not combine equations using it.
        let _c = t.challenge_scalar(b"c");
        let zz = z * z;
        let twos: Vec<_> = util::exp_iter(Scalar::from(2u64)).take(n).collect();
        let ztwo: Vec<_> = util::exp_iter(z).take(m)
            .flat_map(|zj| twos.iter().map(move |p| zj * p)).collect();
        let gs = s.iter().map(|si| -z - a * si);
        let hs = s.iter().rev().zip(util::exp_iter(y.invert())).zip(ztwo.iter())
            .map(|((si, yi), q)| z + yi * (zz * q - b * si));
        let scalars = IntoIterator::into_iter([Scalar::ONE, x]).chain(xs).chain(xis)
            .chain(gs).chain(hs).chain([w * (self.t_x - a * b), -self.e_blinding]);
        let points = IntoIterator::into_iter([self.A.decompress(), self.S.decompress()])
            .chain(self.ipp_proof.L_vec.iter().map(|p| p.decompress()))
            .chain(self.ipp_proof.R_vec.iter().map(|p| p.decompress()))
            .chain(bp.G(n, m).copied().map(Some)).chain(bp.H(n, m).copied().map(Some))
            .chain([Some(pc.B), Some(pc.B_blinding)]);
        let ip = RistrettoPoint::optional_multiscalar_mul(scalars, points)
            .ok_or(ProofError::VerificationError)?;
        let poly = RistrettoPoint::optional_multiscalar_mul(
            IntoIterator::into_iter([x, x * x])
                .chain(util::exp_iter(z).take(m).map(|zj| zz * zj))
                .chain([delta(n, m, &y, &z) - self.t_x, -self.t_x_blinding]),
            IntoIterator::into_iter([self.T_1.decompress(), self.T_2.decompress()])
                .chain(values.iter().map(|v| v.decompress()))
                .chain([Some(pc.B), Some(pc.B_blinding)]),
        ).ok_or(ProofError::VerificationError)?;
        if !independent_residuals_zero(ip, poly) { return Err(ProofError::VerificationError); }
        Ok(())
    }
}

/// Both residuals must vanish, including when their sum would vanish.
pub fn independent_residuals_zero(ip: RistrettoPoint, poly: RistrettoPoint) -> bool {
    ip.is_identity() && poly.is_identity()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;
    #[test]
    fn either_nonzero_residual_is_rejected() {
        let g = PedersenGens::default().B;
        let zero = RistrettoPoint::identity();
        assert!(independent_residuals_zero(zero, zero));
        assert!(!independent_residuals_zero(g, zero));
        assert!(!independent_residuals_zero(zero, g));
        assert!(!independent_residuals_zero(g, -g));
    }
}
