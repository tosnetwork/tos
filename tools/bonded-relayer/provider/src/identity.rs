// Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
//! Local custody and real PQ primitives. Chain eligibility is checked separately.
use crate::{private_io, protocol};
use anyhow::{ensure, Result};
use ark_ff::PrimeField;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fips204::{
    ml_dsa_44,
    traits::{KeyGen as _, SerDes as _},
};
use serde_json::{json, Value};
use shielded_pool_circuit::field::{is_canonical, Fr};
use shielded_pool_wallet::{descriptor::Descriptor, keys::PoolInstance, relayer_quote};
use std::path::Path;

pub struct Identity {
    worker: ml_dsa_44::PrivateKey,
    public: [u8; 1312],
    recipient: PoolInstance,
}
impl Identity {
    pub fn recipient(&self) -> &PoolInstance {
        &self.recipient
    }
    pub fn acceptance(
        &self,
        init: &node_contracts::relayer_bond::BondInit,
        receipt: &chain_block::Cell,
    ) -> Result<Vec<u8>> {
        use fips204::traits::Signer as _;
        let digest = node_contracts::relayer_bond::RelayerBond::signing_hash(
            init,
            node_contracts::relayer_bond::ACCEPTANCE_TAG,
            receipt.repr_hash().as_array(),
        )?;
        Ok(self
            .worker
            .try_sign(&digest, node_contracts::relayer_bond::CONTEXT)
            .map_err(|_| anyhow::anyhow!("acceptance signing refused"))?
            .to_vec())
    }
    pub fn load(directory: &Path, domain: &str, worker_hash: &str) -> Result<Self> {
        let raw = hex::decode(domain)?;
        let encoded: [u8; 32] = raw.try_into().map_err(|_| anyhow::anyhow!("domain width"))?;
        ensure!(is_canonical(&encoded) && encoded.iter().any(|x| *x != 0), "domain field");
        let worker_seed = private_io::seed(&directory.join("worker.seed"))?;
        let owner_seed = private_io::seed(&directory.join("fee-owner.seed"))?;
        ensure!(*worker_seed != *owner_seed, "custody purposes require separate keys");
        let (public, worker) = ml_dsa_44::KG::keygen_from_seed(&worker_seed);
        let public = public.into_bytes();
        ensure!(protocol::hash(&public) == worker_hash, "worker key pin mismatch");
        let recipient = PoolInstance::new(&owner_seed, Fr::from_be_bytes_mod_order(&encoded));
        Ok(Self { worker, public, recipient })
    }
    pub fn descriptor(&self, index: u64) -> Result<Vec<u8>> {
        // Reserve the upper half of the signed-index space for custody-wallet
        // change. Receiving quotes and local spending must not reuse keys.
        ensure!(index < (1u64 << 62), "fee receiving descriptor index bound");
        Ok(Descriptor::issue(&self.recipient, index)?.to_bytes())
    }
    pub fn sign(&self, terms: &[u8]) -> Result<Value> {
        let signature = relayer_quote::sign_terms(&self.worker, terms)?;
        Ok(
            json!({"public_key_b64":STANDARD.encode(self.public), "signature_b64":STANDARD.encode(signature)}),
        )
    }
    pub fn verify(&self, terms: &[u8], public: &str, signature: &str) -> Result<Value> {
        let public = decode(public, 1312)?;
        ensure!(public.as_slice() == self.public, "quote worker mismatch");
        let signature = decode(signature, 2420)?;
        let signature: [u8; 2420] =
            signature.try_into().map_err(|_| anyhow::anyhow!("signature width"))?;
        relayer_quote::verify_terms(&self.public, terms, &signature)?;
        Ok(
            json!({"terms_sha256":protocol::hash(terms), "worker_key_hash":protocol::hash(&self.public)}),
        )
    }
}
pub fn decode(text: &str, exact: usize) -> Result<Vec<u8>> {
    let maximum = exact
        .checked_add(2)
        .and_then(|x| x.checked_div(3))
        .and_then(|x| x.checked_mul(4))
        .ok_or_else(|| anyhow::anyhow!("base64 bound overflow"))?;
    ensure!(text.len() == maximum, "base64 length");
    let bytes = STANDARD.decode(text)?;
    ensure!(bytes.len() == exact && STANDARD.encode(&bytes) == text, "base64 canonical width");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn real_quotes_bind_terms_worker_and_context() -> Result<()> {
        let d = tempfile::tempdir()?;
        for (name, seed) in [("worker.seed", [31u8; 32]), ("fee-owner.seed", [47u8; 32])] {
            let path = d.path().join(name);
            std::fs::write(&path, seed)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let (public, _) = ml_dsa_44::KG::keygen_from_seed(&[31; 32]);
        let hash = protocol::hash(&public.into_bytes());
        let identity = Identity::load(d.path(), &format!("{:064x}", 3), &hash)?;
        let terms = b"{\"purpose\":\"quote\"}";
        let signed = identity.sign(terms)?;
        let public =
            signed["public_key_b64"].as_str().ok_or_else(|| anyhow::anyhow!("public key"))?;
        let signature =
            signed["signature_b64"].as_str().ok_or_else(|| anyhow::anyhow!("signature"))?;
        assert!(identity.verify(terms, public, signature).is_ok());
        assert!(identity.verify(b"{\"purpose\":\"acceptance\"}", public, signature).is_err());
        let mut altered = decode(signature, 2420)?;
        altered[100] ^= 1;
        assert!(identity.verify(terms, public, &STANDARD.encode(altered)).is_err());
        let first = Descriptor::from_bytes(&identity.descriptor(1)?)?;
        let next = Descriptor::from_bytes(&identity.descriptor(2)?)?;
        assert_ne!(first.owner_nf_key_hash, next.owner_nf_key_hash);
        assert!(Identity::load(d.path(), &format!("{:064x}", 3), &"01".repeat(32)).is_err());
        Ok(())
    }
}
