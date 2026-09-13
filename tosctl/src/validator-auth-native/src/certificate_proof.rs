use crate::{
    committee::ChainContext, committee_proof::verify_committee_proof, proof::verify_native_response,
};
use tos_validator_auth::{
    api_semantics::{api_request_id, validate_api_request},
    client::ResponseVerifier,
    codec::{decode, encode, Error, Hash},
    crypto::object_id,
    transfer::ObjectReader,
    types::*,
    verify::VerifiedCertificate,
};

pub struct VerifiedNativeCertificate {
    anchor: Anchor,
    certificate: VerifiedCertificate,
}

/// One call owns its admission result. There is no cross-request verdict cache.
pub struct PreparedNativeCertificate {
    request_id: Hash,
    anchor: Anchor,
    chain: ChainContext,
    expected: Duty,
    verified: Option<VerifiedNativeCertificate>,
}
/// The application supplies independently trusted finality and native duty data.
pub struct NativeCertificateVerifier {
    pub anchor: Anchor,
    pub chain: ChainContext,
    pub expected: Duty,
}
impl ResponseVerifier for NativeCertificateVerifier {
    type Prepared = PreparedNativeCertificate;
    type Output = VerifiedNativeCertificate;
    fn prepare<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
        &self,
        method: u8,
        request: &[u8],
        reader: &mut ObjectReader<F>,
    ) -> Result<Self::Prepared, Error> {
        admit_bytes(request, &[])?;
        let verified = match method {
            12 => {
                validate_api_request(method, request, reader)?;
                if decode::<GetCertificateRequest>(request)?.anchor != self.anchor {
                    return Err(Error("certificate-anchor"));
                }
                None
            }
            13 => Some(verify_native_certificate(
                &decode(request)?,
                &self.anchor,
                &self.chain,
                &self.expected,
                reader,
            )?),
            _ => return Err(Error("unsupported-native-method")),
        };
        Ok(PreparedNativeCertificate {
            request_id: api_request_id(method, request)?,
            anchor: self.anchor.clone(),
            chain: self.chain.clone(),
            expected: self.expected.clone(),
            verified,
        })
    }
    fn verify<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
        &self,
        prepared: Self::Prepared,
        method: u8,
        id: Hash,
        request: &[u8],
        response: &[u8],
        reader: &mut ObjectReader<F>,
    ) -> Result<Self::Output, Error> {
        admit_bytes(request, response)?;
        if prepared.request_id != id
            || api_request_id(method, request)? != id
            || prepared.anchor != self.anchor
            || prepared.chain != self.chain
            || prepared.expected != self.expected
        {
            return Err(Error("certificate-prepared-context"));
        }
        match (method, prepared.verified) {
            (13, Some(verified)) => {
                if decode::<VerifyResult>(response)? != verified.result()? {
                    return Err(Error("verified-result"));
                }
                Ok(verified)
            }
            (12, None) => verify_native_certificate_response(
                method,
                request,
                response,
                &self.anchor,
                &self.chain,
                &self.expected,
                reader,
            ),
            _ => Err(Error("certificate-prepared-context")),
        }
    }
}
impl VerifiedNativeCertificate {
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }
    pub fn certificate(&self) -> &VerifiedCertificate {
        &self.certificate
    }
    pub fn result(&self) -> Result<VerifyResult, Error> {
        let duty = self.certificate.duty();
        Ok(VerifyResult {
            anchor: self.anchor.clone(),
            certificate_id: *self.certificate.certificate_id(),
            policy: duty.policy,
            committee: duty.committee,
            duty: object_id("duty", duty)?,
            signers: self.certificate.signers().to_vec(),
            weight: self.certificate.weight(),
        })
    }
}
/// Finality and the exact native duty are independently pinned by the caller.
/// Peer certificates cannot choose session birth, expected duty or the anchor.
pub fn verify_native_certificate<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    request: &VerifyCertificateRequest,
    anchor: &Anchor,
    chain: &ChainContext,
    expected: &Duty,
    reader: &mut ObjectReader<F>,
) -> Result<VerifiedNativeCertificate, Error> {
    if request.anchor != *anchor {
        return Err(Error("certificate-anchor"));
    }
    if expected.network != chain.network
        || expected.genesis_root != chain.genesis_root
        || expected.genesis_file != chain.genesis_file
        || expected.anchor_mc != anchor.seqno
    {
        return Err(Error("certificate-chain-context"));
    }
    let certificate = decode::<Certificate>(&reader.resolve(&request.certificate, 4)?)?;
    if certificate.duty != *expected {
        return Err(Error("expected-context"));
    }
    let committee = verify_committee_proof(
        &request.committee,
        anchor,
        chain,
        expected.workchain,
        expected.shard,
        expected.catchain,
        reader,
    )?;
    let snapshot = committee.snapshot();
    verify_native_response(
        9,
        &encode(&GetPolicyRequest { anchor: anchor.clone(), policy_id: expected.policy })?,
        &encode(&PolicyResult {
            anchor: anchor.clone(),
            policy: snapshot.policy().clone(),
            proof: request.policy.clone(),
        })?,
        anchor,
        chain.network,
        reader,
    )?;
    let certificate = snapshot.verify_certificate(&certificate, expected)?;
    Ok(VerifiedNativeCertificate { anchor: anchor.clone(), certificate })
}

pub fn verify_native_certificate_response<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    method: u8,
    request: &[u8],
    response: &[u8],
    anchor: &Anchor,
    chain: &ChainContext,
    expected: &Duty,
    reader: &mut ObjectReader<F>,
) -> Result<VerifiedNativeCertificate, Error> {
    admit_bytes(request, response)?;
    match method {
        12 => {
            let q = decode::<GetCertificateRequest>(request)?;
            let r = decode::<CertificateResult>(response)?;
            if q.anchor != *anchor || r.anchor != *anchor {
                return Err(Error("certificate-anchor"));
            }
            if r.era != 1 || r.interface_digest != INTERFACE_FINGERPRINT {
                return Err(Error("certificate-era"));
            }
            let verified = verify_native_certificate(
                &VerifyCertificateRequest {
                    anchor: anchor.clone(),
                    certificate: r.certificate,
                    committee: r.committee,
                    policy: r.policy,
                },
                anchor,
                chain,
                expected,
                reader,
            )?;
            if *verified.certificate().certificate_id() != q.certificate_id {
                return Err(Error("certificate-id"));
            }
            Ok(verified)
        }
        13 => {
            let q = decode::<VerifyCertificateRequest>(request)?;
            let r = decode::<VerifyResult>(response)?;
            let verified = verify_native_certificate(&q, anchor, chain, expected, reader)?;
            if r != verified.result()? {
                return Err(Error("verified-result"));
            }
            Ok(verified)
        }
        _ => Err(Error("unsupported-native-method")),
    }
}

fn admit_bytes(request: &[u8], response: &[u8]) -> Result<(), Error> {
    if request.len() > 2_000_000 || response.len() > 2_000_000 {
        return Err(Error("api-binary-bound"));
    }
    Ok(())
}
