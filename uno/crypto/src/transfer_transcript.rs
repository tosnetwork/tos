//! Unactivated private-transfer transcript candidate, not a frozen wire codec.
//! Integers are big-endian; every byte string has a u64 byte-length prefix.
//! Hybrid ciphertext bytes are bound but their encryption correctness is not
//! established here. The caller must supply an authenticated profile and limits.
use crate::{
    context::PublicContext,
    decode::{decode_bundle, DecodeError, EncodedBundle},
    FixedVerifier, VerificationError,
};
use orchard::bundle::BundleVersion;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferDomain {
    pub wire_version: u32,
    pub scheme_id: u32,
    pub engine_selector: u32,
    pub engine_version: u32,
    pub network_id: [u8; 32],
    pub global_id: i32,
    pub workchain_id: i32,
    pub chain_id: [u8; 32],
    pub encryption_profile: u32,
}

#[derive(Clone)]
pub struct TransferHeader {
    pub domain: TransferDomain,
    pub expiry_height: u64,
    pub nonce: [u8; 32],
    pub fee: u128,
}

#[derive(Clone, Copy)]
pub struct TranscriptLimits {
    pub max_actions: usize,
    pub max_proof_bytes: usize,
    pub kem_ciphertext_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TranscriptError {
    Domain,
    Shape,
    Length,
    Decode(DecodeError),
    Verification(VerificationError),
}

#[derive(Debug, PartialEq, Eq)]
pub struct TransferDigests {
    pub txid: [u8; 32],
    pub sighash: [u8; 32],
    pub authorization: [u8; 32],
}

fn bytes(hash: &mut blake3::Hasher, value: &[u8]) -> Result<(), TranscriptError> {
    let length = u64::try_from(value.len()).map_err(|_| TranscriptError::Length)?;
    hash.update(&length.to_be_bytes());
    hash.update(value);
    Ok(())
}

fn domain(label: &[u8]) -> Result<blake3::Hasher, TranscriptError> {
    let mut hash = blake3::Hasher::new();
    bytes(&mut hash, b"tos-uno-privacy-v1/experimental-transfer-v0")?;
    bytes(&mut hash, label)?;
    Ok(hash)
}

// Keep admission and transcript encoding in one mapping. New profiles require
// an explicit ID decision instead of inheriting the existing profile byte.
fn bundle_profile_id(profile: BundleVersion) -> Result<u8, TranscriptError> {
    if profile == BundleVersion::orchard_v2() {
        Ok(0)
    } else {
        Err(TranscriptError::Shape)
    }
}

pub fn transfer_digests(
    header: &TransferHeader,
    bundle: &EncodedBundle<'_>,
    kem: &[&[u8]],
    limits: TranscriptLimits,
) -> Result<TransferDigests, TranscriptError> {
    let profile_id = bundle_profile_id(bundle.profile)?;
    if bundle.actions.is_empty()
        || bundle.actions.len() > limits.max_actions
        || bundle.actions.len() != kem.len()
        || limits.kem_ciphertext_bytes == 0
        || kem.iter().any(|item| item.len() != limits.kem_ciphertext_bytes)
        || bundle.proof.len() > limits.max_proof_bytes
    {
        return Err(TranscriptError::Shape);
    }
    let mut hash = domain(b"txid")?;
    let d = &header.domain;
    for value in
        [d.wire_version, d.scheme_id, d.engine_selector, d.engine_version, d.encryption_profile]
    {
        hash.update(&value.to_be_bytes());
    }
    bytes(&mut hash, &d.network_id)?;
    hash.update(&d.global_id.to_be_bytes());
    hash.update(&d.workchain_id.to_be_bytes());
    bytes(&mut hash, &d.chain_id)?;
    // Private transfer only: explicit prototype kind, zero public in/out and
    // absent external reference, destination and refund plan. No generic mint.
    hash.update(&[0]);
    hash.update(&header.expiry_height.to_be_bytes());
    bytes(&mut hash, &header.nonce)?;
    hash.update(&header.fee.to_be_bytes());
    hash.update(&0u128.to_be_bytes());
    hash.update(&0u128.to_be_bytes());
    hash.update(&[0, 0, 0]);
    hash.update(&[profile_id, bundle.flags]);
    hash.update(&bundle.value_balance.to_be_bytes());
    bytes(&mut hash, &bundle.anchor)?;
    let count = u64::try_from(bundle.actions.len()).map_err(|_| TranscriptError::Length)?;
    hash.update(&count.to_be_bytes());
    for (action, kem) in bundle.actions.iter().zip(kem) {
        for field in [
            &action.cv_net[..],
            &action.nullifier,
            &action.rk,
            &action.cmx,
            &action.epk,
            &action.enc_ciphertext,
            &action.out_ciphertext,
            kem,
        ] {
            bytes(&mut hash, field)?;
        }
    }
    let txid = *hash.finalize().as_bytes();
    let mut signed = domain(b"sighash")?;
    bytes(&mut signed, &txid)?;
    let sighash = *signed.finalize().as_bytes();
    let mut auth = domain(b"authorization")?;
    bytes(&mut auth, &txid)?;
    bytes(&mut auth, bundle.proof)?;
    for action in bundle.actions {
        bytes(&mut auth, &action.spend_signature)?;
    }
    bytes(&mut auth, &bundle.binding_signature)?;
    Ok(TransferDigests { txid, sighash, authorization: *auth.finalize().as_bytes() })
}

// The same parsed bytes determine the transcript and every crypto instance.
// No externally supplied sighash enters this verification path. Context expiry,
// fee policy, state and canonical Cell admission remain the enclosing host's job.
pub fn verify_transfer(
    verifier: &FixedVerifier,
    expected: &TransferDomain,
    header: &TransferHeader,
    bundle: &EncodedBundle<'_>,
    kem: &[&[u8]],
    limits: TranscriptLimits,
) -> Result<TransferDigests, TranscriptError> {
    if expected != &header.domain {
        return Err(TranscriptError::Domain);
    }
    let digests = transfer_digests(header, bundle, kem, limits)?;
    let decoded = decode_bundle(bundle, limits.max_actions, limits.max_proof_bytes)
        .map_err(TranscriptError::Decode)?;
    verifier
        .verify_in_context(
            &decoded,
            PublicContext::Transfer { fee: header.fee },
            &digests.sighash,
            limits.max_actions,
            limits.max_proof_bytes,
        )
        .map_err(TranscriptError::Verification)?;
    Ok(digests)
}

#[cfg(test)]
pub(crate) fn test_header() -> TransferHeader {
    TransferHeader {
        domain: TransferDomain {
            wire_version: 2,
            scheme_id: 0,
            engine_selector: 0x554e4f32,
            engine_version: 1,
            network_id: [11; 32],
            global_id: -239,
            workchain_id: 2,
            chain_id: [12; 32],
            encryption_profile: 0,
        },
        expiry_height: 64,
        nonce: [13; 32],
        fee: 100,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::EncodedAction;

    #[test]
    fn primitive_known_answers_and_length_separation() {
        assert_eq!(
            blake3::hash(&[]).to_hex().as_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        let mut hash = blake3::Hasher::new();
        hash.update(&[0]);
        hash.update(&[1, 2]);
        assert_eq!(
            hash.finalize().to_hex().as_str(),
            "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
        );
        let mut first = domain(b"test").expect("domain");
        let mut second = first.clone();
        bytes(&mut first, b"ab").expect("field");
        bytes(&mut first, b"c").expect("field");
        bytes(&mut second, b"a").expect("field");
        bytes(&mut second, b"bc").expect("field");
        assert_ne!(first.finalize(), second.finalize());
    }

    #[test]
    fn semantic_fields_and_authorization_are_separate() {
        let original = test_header();
        let actions = vec![EncodedAction {
            cv_net: [1; 32],
            nullifier: [2; 32],
            rk: [3; 32],
            cmx: [4; 32],
            epk: [5; 32],
            enc_ciphertext: [6; 580],
            out_ciphertext: [7; 80],
            spend_signature: [8; 64],
        }];
        let limits =
            TranscriptLimits { max_actions: 2, max_proof_bytes: 20, kem_ciphertext_bytes: 4 };
        let digest = |header: &TransferHeader,
                      actions: &[EncodedAction],
                      flags,
                      balance,
                      anchor,
                      proof: &[u8],
                      binding,
                      kem: &[&[u8]]| {
            transfer_digests(
                header,
                &EncodedBundle {
                    profile: BundleVersion::orchard_v2(),
                    flags,
                    value_balance: balance,
                    anchor,
                    actions,
                    proof,
                    binding_signature: binding,
                },
                kem,
                limits,
            )
            .expect("transcript")
        };
        let base = digest(&original, &actions, 3, 100, [9; 32], &[10], [11; 64], &[&[12; 4]]);
        assert_eq!(
            blake3::Hash::from_bytes(base.txid).to_hex().as_str(),
            "3c9739ea98249dcbd4e9dd7a1f7b77f3b5caa5ee2f121d806408575fe6fc7f86"
        );
        assert_eq!(
            blake3::Hash::from_bytes(base.sighash).to_hex().as_str(),
            "86cc4fe776711aeca3a9165fdff6fadd25d266eed59d9d965a6fc91543c67d6f"
        );
        assert_eq!(
            blake3::Hash::from_bytes(base.authorization).to_hex().as_str(),
            "48ecf7dde8a99ab782ebd8be643fab87f7b269b757c5ee238dc0ddee30044eb5"
        );
        macro_rules! changed_header {
            ($field:ident $(.$nested:ident)?) => {{
                let mut header = original.clone();
                header.$field $(.$nested)? += 1;
                assert_ne!(base.txid, digest(&header, &actions, 3, 100, [9;32], &[10], [11;64], &[&[12;4]]).txid);
            }};
        }
        changed_header!(expiry_height);
        let mut changed_fee = original.clone();
        changed_fee.fee = original.fee.checked_add(1).expect("fixture fee");
        assert_ne!(
            base.txid,
            digest(&changed_fee, &actions, 3, 100, [9; 32], &[10], [11; 64], &[&[12; 4]]).txid
        );
        changed_header!(domain.wire_version);
        changed_header!(domain.scheme_id);
        changed_header!(domain.engine_selector);
        changed_header!(domain.engine_version);
        changed_header!(domain.global_id);
        changed_header!(domain.workchain_id);
        changed_header!(domain.encryption_profile);
        for index in 0..3 {
            let mut header = original.clone();
            match index {
                0 => header.nonce[0] ^= 1,
                1 => header.domain.network_id[0] ^= 1,
                _ => header.domain.chain_id[0] ^= 1,
            }
            assert_ne!(
                base.txid,
                digest(&header, &actions, 3, 100, [9; 32], &[10], [11; 64], &[&[12; 4]]).txid
            );
        }
        for index in 0..7 {
            let mut altered = actions.clone();
            match index {
                0 => altered[0].cv_net[0] ^= 1,
                1 => altered[0].nullifier[0] ^= 1,
                2 => altered[0].rk[0] ^= 1,
                3 => altered[0].cmx[0] ^= 1,
                4 => altered[0].epk[0] ^= 1,
                5 => altered[0].enc_ciphertext[0] ^= 1,
                _ => altered[0].out_ciphertext[0] ^= 1,
            }
            assert_ne!(
                base.txid,
                digest(&original, &altered, 3, 100, [9; 32], &[10], [11; 64], &[&[12; 4]]).txid
            );
        }
        for altered in [
            digest(&original, &actions, 2, 100, [9; 32], &[10], [11; 64], &[&[12; 4]]),
            digest(&original, &actions, 3, 101, [9; 32], &[10], [11; 64], &[&[12; 4]]),
            digest(&original, &actions, 3, 100, [8; 32], &[10], [11; 64], &[&[12; 4]]),
            digest(&original, &actions, 3, 100, [9; 32], &[10], [11; 64], &[&[13; 4]]),
        ] {
            assert_ne!(base.txid, altered.txid);
            assert_ne!(base.sighash, altered.sighash);
        }
        let mut signatures = actions.clone();
        signatures[0].spend_signature[0] ^= 1;
        for altered in [
            digest(&original, &actions, 3, 100, [9; 32], &[10, 11], [11; 64], &[&[12; 4]]),
            digest(&original, &actions, 3, 100, [9; 32], &[10], [12; 64], &[&[12; 4]]),
            digest(&original, &signatures, 3, 100, [9; 32], &[10], [11; 64], &[&[12; 4]]),
        ] {
            assert_eq!(base.txid, altered.txid);
            assert_eq!(base.sighash, altered.sighash);
            assert_ne!(base.authorization, altered.authorization);
        }
        assert_ne!(base.txid, base.sighash);
        let mut pair = vec![actions[0].clone(), actions[0].clone()];
        pair[1].cmx[0] ^= 1;
        let ordered =
            digest(&original, &pair, 3, 100, [9; 32], &[10], [11; 64], &[&[12; 4], &[13; 4]]);
        assert_ne!(base.txid, ordered.txid);
        assert_ne!(
            ordered.txid,
            digest(&original, &pair, 3, 100, [9; 32], &[10], [11; 64], &[&[13; 4], &[12; 4]]).txid
        );
        pair.reverse();
        assert_ne!(
            ordered.txid,
            digest(&original, &pair, 3, 100, [9; 32], &[10], [11; 64], &[&[12; 4], &[13; 4]]).txid
        );
        let mut raw = EncodedBundle {
            profile: BundleVersion::orchard_v2(),
            flags: 3,
            value_balance: 100,
            anchor: [9; 32],
            actions: &actions,
            proof: &[10],
            binding_signature: [11; 64],
        };
        assert_eq!(bundle_profile_id(BundleVersion::orchard_v2()), Ok(0));
        for profile in [BundleVersion::orchard_insecure_v1(), BundleVersion::orchard_v3(),
                        BundleVersion::ironwood_v3()] {
            assert_eq!(bundle_profile_id(profile), Err(TranscriptError::Shape));
            raw.profile = profile;
            assert_eq!(transfer_digests(&original, &raw, &[&[12; 4]], limits), Err(TranscriptError::Shape));
        }
        raw.profile = BundleVersion::orchard_v2();
        assert_eq!(transfer_digests(&original, &raw, &[], limits), Err(TranscriptError::Shape));
        assert_eq!(
            transfer_digests(&original, &raw, &[&[0; 3]], limits),
            Err(TranscriptError::Shape)
        );
        assert_eq!(
            transfer_digests(
                &original,
                &raw,
                &[&[0; 4]],
                TranscriptLimits { max_actions: 0, ..limits }
            ),
            Err(TranscriptError::Shape)
        );
        assert_eq!(
            transfer_digests(
                &original,
                &raw,
                &[&[0; 4]],
                TranscriptLimits { max_proof_bytes: 0, ..limits }
            ),
            Err(TranscriptError::Shape)
        );
    }
}
