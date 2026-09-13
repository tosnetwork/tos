use crate::codec::{encode, Error, Hash, Wire};
use sha2::{Digest, Sha256};
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
pub struct AdmittedKey(tos_validator_auth_crypto::AdmittedKey);
impl AdmittedKey {
    pub fn admit(bytes: &[u8]) -> Result<Self, Error> {
        tos_validator_auth_crypto::AdmittedKey::admit(bytes)
            .map(Self)
            .map_err(|_| Error("public-key"))
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.0.verify(message, signature)
    }
    pub fn bytes(&self) -> &Hash {
        self.0.bytes()
    }
}
