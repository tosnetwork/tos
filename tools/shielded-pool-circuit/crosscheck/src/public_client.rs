//! Offline public-pool proving. This path has no transport, seeded fixture
//! constructor, or private-data output. Submission uses the existing wallet
//! and `Transact` serializers after an operator has verified the snapshot.

use ark_bls12_381::Bls12_381;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use shielded_pool_ceremony::{
    audit::Audited,
    record::{key_digest, Directory},
};
use shielded_pool_circuit::{
    circuit::{ShieldedTransactionCircuit, TransactionWitness},
    field::Fr,
    groth16::{self, CanonicalProof},
    public_inputs::PublicInputs,
    wire,
};

use crate::{CrossCheckError, Result};

fn refused(message: impl Into<String>) -> CrossCheckError {
    CrossCheckError::Fixture(message.into())
}

fn draw_seed(
    mut fill: impl FnMut(&mut [u8]) -> std::result::Result<(), String>,
) -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    fill(&mut seed).map_err(refused)?;
    Ok(seed)
}

fn rng_with_entropy(
    fill: impl FnMut(&mut [u8]) -> std::result::Result<(), String>,
) -> Result<ChaCha20Rng> {
    let seed = draw_seed(fill)?;
    Ok(ChaCha20Rng::from_seed(seed))
}

fn os_rng() -> Result<ChaCha20Rng> {
    rng_with_entropy(|bytes| {
        OsRng.try_fill_bytes(bytes).map_err(|_| "OS entropy unavailable".into())
    })
}

/// Uniform, non-zero fields for intent nonces and note secrets. No fallback
/// is available when the OS entropy source fails.
pub fn fresh_nonzero_field() -> Result<Fr> {
    let mut rng = os_rng()?;
    loop {
        let value = Fr::rand(&mut rng);
        if !value.is_zero() {
            return Ok(value);
        }
    }
}

/// Holds a public proving key and one explicit execution domain. It never
/// holds wallet signing seeds, serializes witnesses, or broadcasts messages.
pub struct PublicClient {
    key: ProvingKey<Bls12_381>,
    domain: Fr,
}

impl PublicClient {
    /// `audited` must come from the complete ceremony audit; `expected_vk`
    /// comes from the reviewed deployment manifest, not from an endpoint.
    pub fn load(
        directory: &Directory,
        audited: &Audited,
        expected_vk: &str,
        global_id: i32,
        pool_account: &[u8; 32],
    ) -> Result<Self> {
        if !audited.is_finished() {
            return Err(refused("public client requires a finished audited ceremony"));
        }
        if expected_vk != audited.vk_sha256() {
            return Err(refused("audited VK does not match the reviewed deployment"));
        }
        let key = directory.read_key().map_err(|_| refused("cannot read ceremony proving key"))?;
        let digest = key_digest(&key).map_err(|_| refused("cannot hash ceremony proving key"))?;
        if digest != audited.record().key_sha256 {
            return Err(refused("proving key changed after audit"));
        }
        let canonical = groth16::canonical_verifying_key(&key.vk)
            .map_err(|_| refused("cannot encode audited VK"))?;
        if canonical.bytes != audited.verifying_key() {
            return Err(refused("proving key carries a different VK"));
        }
        Ok(Self { key, domain: wire::execution_domain(global_id, pool_account) })
    }

    pub fn execution_domain(&self) -> Fr {
        self.domain
    }

    /// `now` is the execution-time context of the verified snapshot. The
    /// contract still checks validity at inclusion; a delayed body must be
    /// rebuilt, never silently retargeted to another domain or expiry.
    pub fn prove(
        &self,
        public: PublicInputs,
        witness: TransactionWitness,
        now: u32,
    ) -> Result<CanonicalProof> {
        validate(&public, &witness, self.domain, now)?;
        let mut rng = os_rng()?;
        let circuit = ShieldedTransactionCircuit::new(public, witness);
        let proof = Groth16::<Bls12_381>::prove(&self.key, circuit, &mut rng)
            .map_err(|_| refused("private proof construction failed"))?;
        let valid = groth16::verify(&self.key.vk, &public, &proof)
            .map_err(|_| refused("private proof verification failed"))?;
        if !valid {
            return Err(refused("constructed proof does not verify"));
        }
        groth16::CanonicalProof::from_proof(&proof)
            .map_err(|_| refused("cannot encode verified proof"))
    }
}

fn validate(
    public: &PublicInputs,
    witness: &TransactionWitness,
    domain: Fr,
    now: u32,
) -> Result<()> {
    if public.execution_domain != domain {
        return Err(refused("proof execution domain differs from the reviewed deployment"));
    }
    if witness.intent_nonce.is_zero()
        || witness.outputs.iter().any(|note| note.note_secret.is_zero())
    {
        return Err(refused("intent nonce and every output note secret must be non-zero"));
    }
    let bytes = public.valid_until.into_bigint().to_bytes_be();
    let mut encoded = [0u8; 32];
    if bytes.len() > encoded.len() {
        return Err(refused("intent expiry exceeds uint32"));
    }
    let start = encoded.len().checked_sub(bytes.len()).ok_or_else(|| refused("expiry width"))?;
    encoded[start..].copy_from_slice(&bytes);
    if encoded[..28].iter().any(|byte| *byte != 0) {
        return Err(refused("intent expiry exceeds uint32"));
    }
    let expiry = u32::from_be_bytes(encoded[28..].try_into().map_err(|_| refused("expiry width"))?);
    if expiry.checked_sub(now).is_none_or(|remaining| remaining > 3600) {
        return Err(refused("intent is expired or exceeds its one-hour window"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn proof_randomness_uses_every_byte_of_fallible_full_width_entropy() {
        let input = core::array::from_fn::<_, 32, _>(|index| index as u8);
        let seed = draw_seed(|bytes| {
            assert_eq!(bytes.len(), 32, "proof entropy was truncated");
            bytes.copy_from_slice(&input);
            Ok(())
        })
        .expect("entropy");
        assert_eq!(seed, input, "proof entropy was discarded or replaced");
        assert!(draw_seed(|_| Err("entropy unavailable".into())).is_err());
    }

    #[test]
    fn proof_randomness_depends_on_prefix_as_well_as_final_byte() {
        let mut a = rng_with_entropy(|bytes| {
            bytes.fill(1);
            bytes[31] = 7;
            Ok(())
        })
        .expect("first seed");
        let mut b = rng_with_entropy(|bytes| {
            bytes.fill(2);
            bytes[31] = 7;
            Ok(())
        })
        .expect("second seed");
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_ne!(x, y, "proof randomness collapsed to an eight-bit seed");
    }

    #[test]
    fn fresh_fields_are_nonzero_and_do_not_repeat() {
        let a = fresh_nonzero_field().expect("OS field");
        let b = fresh_nonzero_field().expect("OS field");
        assert!(!a.is_zero());
        assert!(!b.is_zero());
        assert_ne!(a, b);
    }
}
