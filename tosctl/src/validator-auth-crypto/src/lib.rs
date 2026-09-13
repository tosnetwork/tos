// Pure Ed25519 C0 primitive. Callers enforce message bounds and authority.
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Digest, Sha512};
#[derive(Clone, Copy, Debug)]
pub struct InvalidKey;
#[derive(Clone, Debug)]
pub struct AdmittedKey {
    bytes: [u8; 32],
    point: EdwardsPoint,
}
fn point(bytes: [u8; 32]) -> Option<EdwardsPoint> {
    let p = CompressedEdwardsY(bytes).decompress()?;
    if p.compress().to_bytes() != bytes {
        return None;
    }
    Some(p)
}
impl AdmittedKey {
    pub fn admit(bytes: &[u8]) -> Result<Self, InvalidKey> {
        let raw: [u8; 32] = bytes.try_into().map_err(|_| InvalidKey)?;
        let p = point(raw).ok_or(InvalidKey)?;
        if p == EdwardsPoint::identity() || !p.is_torsion_free() {
            return Err(InvalidKey);
        }
        Ok(Self { bytes: raw, point: p })
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut r = [0; 32];
        r.copy_from_slice(&signature[..32]);
        let Some(rpoint) = point(r) else { return false };
        let mut raw_s = [0; 32];
        raw_s.copy_from_slice(&signature[32..]);
        let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(raw_s)) else {
            return false;
        };
        let mut state = Sha512::new();
        state.update(r);
        state.update(self.bytes);
        state.update(message);
        let wide: [u8; 64] = state.finalize().into();
        let h = Scalar::from_bytes_mod_order_wide(&wide);
        s * ED25519_BASEPOINT_POINT == rpoint + h * self.point
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}
