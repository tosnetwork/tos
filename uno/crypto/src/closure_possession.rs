//! Second independent M3 entry added outside D34 relation-family review.
//! Correspondence tests do not constitute a reliability argument.
//! DLEQ proves knowledge of the same s with sP=H and sD=C: zero plaintext
//! under the admitted v<l invariant, not pending emptiness or no obligations.
//! Those are host checks against authenticated state. Key origin is unverifiable.
//!
//! Randomized zero is (rH,rP), not two identity points unless r=0. Requiring
//! all-zero ciphertext would expose zero balances and impose fixed randomness.
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar, traits::IsIdentity};
use sha2::{Digest, Sha512};
use crate::ffi::{AbiStatus as Error, ClosurePossessionRequestV1};

fn challenge(r: &ClosurePossessionRequestV1, r1: &[u8;32], r2: &[u8;32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"TOS/UNO/CLOSE/KEY-POSSESSION/v1");
    h.update(r.domain);
    h.update(r.global_id.to_be_bytes()); h.update(r.genesis_hash);
    h.update(r.workchain_id.to_be_bytes()); h.update(r.account); h.update(r.incarnation);
    h.update(r.asset); h.update(r.custody); h.update(r.policy);
    h.update(r.schema_version.to_be_bytes()); h.update(r.relation_profile.to_be_bytes());
    h.update(r.proof_profile.to_be_bytes()); h.update(r.key_epoch.to_be_bytes());
    h.update(r.auth_nonce.to_be_bytes()); h.update(r.available_revision.to_be_bytes());
    h.update(r.public_key); h.update(PedersenGens::default().B_blinding.compress().as_bytes());
    h.update(r.handle); h.update(r.commitment); h.update(r1); h.update(r2);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

pub(crate) fn verify(r: &ClosurePossessionRequestV1) -> Result<(), Error> {
    let decode = |b| CompressedRistretto(b).decompress().ok_or(Error::UNO_CRYPTO_DECODE);
    let p = decode(r.public_key)?;
    let d = decode(r.handle)?;
    // D=identity would make the second base degenerate. Registration's initial
    // (0,0) is not accepted as a substitute for this closure authorization.
    if p.is_identity() || d.is_identity() { return Err(Error::UNO_CRYPTO_DECODE); }
    let c_point = decode(r.commitment)?;
    let r1_bytes: [u8;32] = r.proof[..32].try_into().unwrap();
    let r2_bytes: [u8;32] = r.proof[32..64].try_into().unwrap();
    let r1 = decode(r1_bytes)?;
    let r2 = decode(r2_bytes)?;
    let z = Option::<Scalar>::from(Scalar::from_canonical_bytes(r.proof[64..].try_into().unwrap()))
        .ok_or(Error::UNO_CRYPTO_DECODE)?;
    let c = challenge(r, &r1_bytes, &r2_bytes);
    if z*p != r1 + c*PedersenGens::default().B_blinding || z*d != r2 + c*c_point {
        return Err(Error::UNO_CRYPTO_VERIFY);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::uno_crypto_verify_closure_possession_v1;
    fn proof(value: u64) -> ClosurePossessionRequestV1 {
        // Fixed test witnesses only; not a wallet nonce-generation API.
        let s = Scalar::from(71u64); let k = Scalar::from(93u64); let random = Scalar::from(17u64);
        let generators = PedersenGens::default();
        let p = s.invert()*generators.B_blinding;
        let d = random*p;
        let commitment = random*generators.B_blinding + Scalar::from(value)*generators.B;
        let r1 = (k*p).compress().to_bytes(); let r2 = (k*d).compress().to_bytes();
        let mut r = ClosurePossessionRequestV1 { abi_version:1, domain:[7;80], global_id:-23903,
            genesis_hash:[1;32], workchain_id:2, account:[2;32], incarnation:[3;32], asset:[4;32],
            custody:[5;32], policy:[6;32], schema_version:1, relation_profile:1, proof_profile:2,
            key_epoch:0, auth_nonce:3, available_revision:4, public_key:p.compress().to_bytes(),
            commitment:commitment.compress().to_bytes(), handle:d.compress().to_bytes(), proof:[0;96] };
        let z = k + challenge(&r,&r1,&r2)*s;
        r.proof[..32].copy_from_slice(&r1); r.proof[32..64].copy_from_slice(&r2);
        r.proof[64..].copy_from_slice(&z.to_bytes()); r
    }
    #[test]
    fn randomized_zero_and_nonzero() {
        let r = proof(0);
        assert_ne!(r.commitment,[0;32]); assert_ne!(r.handle,[0;32]);
        assert_eq!(unsafe { uno_crypto_verify_closure_possession_v1(&r) },0);
        assert_eq!(unsafe { uno_crypto_verify_closure_possession_v1(&proof(1)) },Error::UNO_CRYPTO_VERIFY as u32);
    }
    #[test]
    fn state_binding_and_degenerate_inputs() {
        let original = proof(0);
        let changes: &[fn(&mut ClosurePossessionRequestV1)] = &[
            |r| r.domain[0]^=1, |r| r.account[0]^=1, |r| r.incarnation[0]^=1,
            |r| r.key_epoch+=1, |r| r.auth_nonce+=1, |r| r.available_revision+=1,
            |r| r.proof[0]^=1, |r| r.proof[32]^=1, |r| r.proof[64]^=1,
        ];
        for change in changes { let mut r=original; change(&mut r);
            assert_ne!(unsafe { uno_crypto_verify_closure_possession_v1(&r) },0); }
        let mut r=original; r.handle=[0;32];
        assert_eq!(unsafe { uno_crypto_verify_closure_possession_v1(&r) },Error::UNO_CRYPTO_DECODE as u32);
        r=original; r.public_key=[0;32];
        assert_eq!(unsafe { uno_crypto_verify_closure_possession_v1(&r) },Error::UNO_CRYPTO_DECODE as u32);
        r=original; r.proof[64..].fill(255);
        assert_eq!(unsafe { uno_crypto_verify_closure_possession_v1(&r) },Error::UNO_CRYPTO_DECODE as u32);
        assert_eq!(unsafe { uno_crypto_verify_closure_possession_v1(std::ptr::null()) },Error::UNO_CRYPTO_ARGUMENTS as u32);
    }
}
