use crate::codec::{encode, Error, Hash, Wire};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Digest, Sha256, Sha512};
pub fn digest(domain: &str, bytes: &[u8]) -> Result<Hash, Error> {
    if domain.len() > 64 || bytes.len() > 67108864 {
        return Err(Error("hash-bound"));
    }
    let mut state = Sha256::new();
    state.update(b"TOS/P0/");
    state.update(domain.as_bytes());
    state.update(b"/v1\0");
    state.update(bytes);
    Ok(state.finalize().into())
}
pub fn object_id<T: Wire>(domain: &str, value: &T) -> Result<Hash, Error> {
    digest(domain, &encode(value)?)
}
#[derive(Clone, Debug)]
pub struct AdmittedKey {
    bytes: Hash,
    point: EdwardsPoint,
}
fn point(bytes: Hash) -> Option<EdwardsPoint> {
    let p = CompressedEdwardsY(bytes).decompress()?;
    if p.compress().to_bytes() != bytes {
        return None;
    }
    Some(p)
}
impl AdmittedKey {
    pub fn admit(bytes: &[u8]) -> Result<Self, Error> {
        let raw: Hash = bytes.try_into().map_err(|_| Error("public-key"))?;
        let p = point(raw).ok_or(Error("public-key"))?;
        if p == EdwardsPoint::identity() || !p.is_torsion_free() {
            return Err(Error("public-key"));
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
    pub fn bytes(&self) -> &Hash {
        &self.bytes
    }
}
