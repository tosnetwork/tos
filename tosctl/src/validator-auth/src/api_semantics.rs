use crate::{
    api_types::validate_api_binary,
    codec::{decode, encode, Error, Hash, Wire},
    crypto::{digest, object_id},
    service_auth::{validate_permit_context, validate_request_state},
    transfer::{validate_chunk, validate_manifest, ObjectReader},
    types::*,
    verify::{key_reference, signing_statement, validate_payload, MAX_WEIGHT},
};
use std::collections::BTreeSet;
fn anchor(a: &Anchor) -> Result<(), Error> {
    if a.seqno == u32::MAX || [a.root, a.file, a.state].contains(&[0; 32]) {
        return Err(Error("anchor"));
    }
    Ok(())
}
fn suites(values: &[Suite]) -> bool {
    let mut previous = (0, 0);
    for s in values {
        let current = (s.suite, s.parameters);
        if current <= previous || s.suite == 0 || s.parameters == 0 {
            return false;
        }
        previous = current;
    }
    true
}
fn service_components(values: &[ServiceComponent]) -> Result<(), Error> {
    if values.is_empty() || values.len() > 2 {
        return Err(Error("service-components"));
    }
    let mut previous = (0, 0);
    for c in values {
        let current = (c.suite, c.parameters);
        if current <= previous
            || c.suite == 0
            || c.parameters == 0
            || c.key_id == [0; 32]
            || c.signature.is_empty()
            || (current == (1, 1) && c.signature.len() != 64)
        {
            return Err(Error("service-components"));
        }
        previous = current;
    }
    Ok(())
}
fn permit_shape(p: &Permit, method: u8, fence: u64, subject: &Hash) -> Result<(), Error> {
    if p.body.method != method || p.body.subject != *subject {
        return Err(Error("permit-association"));
    }
    validate_permit_context(&p.body, p.body.anchor.seqno, fence, true)?;
    service_components(&p.components)
}
fn sign_template(q: &SignRequest) -> Result<Envelope, Error> {
    let e = decode::<Envelope>(&q.envelope_template)?;
    if e.record.identity == [0; 32]
        || e.record.components.is_empty()
        || q.fence == 0
        || e.record.components.len() != q.key_handles.len()
    {
        return Err(Error("sign-template"));
    }
    let mut previous = (0, 0);
    let mut handles = BTreeSet::new();
    for (c, handle) in e.record.components.iter().zip(&q.key_handles) {
        let current = (c.suite, c.parameters);
        if current <= previous
            || c.suite == 0
            || c.parameters == 0
            || c.epoch == 0
            || c.key_id == [0; 32]
            || !c.signature.is_empty()
            || *handle == [0; 32]
            || !handles.insert(handle)
        {
            return Err(Error("sign-template"));
        }
        previous = current;
    }
    validate_payload(&e.duty, &e.payload)?;
    let statement = signing_statement(&e.duty, &e.record)?;
    if q.request_id != digest("sign-request", &statement)? {
        return Err(Error("sign-request-id"));
    }
    permit_shape(&q.permit, 5, q.fence, &digest("statement", &statement)?)?;
    let p = &q.permit.body;
    let d = &e.duty;
    if p.network != d.network
        || p.genesis_root != d.genesis_root
        || p.genesis_file != d.genesis_file
        || p.policy != d.policy
        || p.committee != d.committee
        || p.session != d.session
        || p.identity != e.record.identity
        || p.anchor.seqno < d.anchor_mc
    {
        return Err(Error("sign-permit-association"));
    }
    Ok(e)
}
fn proof_shape<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    p: &Proofref,
    a: &Anchor,
    kind: u8,
    id: &Hash,
    reader: &mut ObjectReader<F>,
) -> Result<(), Error> {
    if p.anchor != *a || p.kind != kind || p.object_id != *id {
        return Err(Error("proof-binding"));
    }
    let bytes = reader.resolve(&p.proof, 5)?;
    if digest("proof", &bytes)? != p.proof_hash {
        return Err(Error("proof-hash"));
    }
    Ok(())
}
fn certificate<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    v: &ObjectValue,
    reader: &mut ObjectReader<F>,
) -> Result<Certificate, Error> {
    decode(&reader.resolve(v, 4)?)
}
struct ReceiptLink {
    method: u8,
    fence: u64,
    subject: Hash,
    context: Hash,
}
fn receipt<B: Wire>(r: &Receipt, request: &[u8], body: &B, link: ReceiptLink) -> Result<(), Error> {
    let mut bytes = vec![link.method];
    bytes.extend_from_slice(&encode(body)?);
    let b = &r.body;
    if b.request_id != api_request_id(link.method, request)?
        || b.method != link.method
        || b.subject != link.subject
        || b.context_id != link.context
        || b.result_hash != digest("api-result", &bytes)?
        || b.fence != link.fence
        || b.journal_sequence == 0
        || b.state != 2
        || [b.issuer, b.service_policy, b.audience].contains(&[0; 32])
    {
        return Err(Error("result-receipt-binding"));
    }
    service_components(&r.components)
}
fn anchor_prefix(raw: &[u8]) -> Result<Anchor, Error> {
    decode(raw.get(8..8 + Anchor::MIN_SIZE).ok_or(Error("truncated"))?)
}
fn scalar_request(method: u8, raw: &[u8]) -> Result<(), Error> {
    validate_api_binary(method, false, false, raw)?;
    match method {
        3 => {
            let q = decode::<PrepareRequest>(raw)?;
            if q.preparation_id == [0; 32]
                || q.identity == [0; 32]
                || !(1..=5).contains(&q.role)
                || q.suite == 0
                || q.parameters == 0
                || q.epoch == 0
                || q.epoch == u64::MAX
                || q.valid_from >= q.valid_until
                || q.fence == 0
            {
                return Err(Error("preparation"));
            }
            if q.mode > 1 || (q.provider_handle == [0; 32]) != (q.mode == 0) {
                return Err(Error("preparation-mode"));
            }
        }
        4 => {
            let q = decode::<StageRequest>(raw)?;
            if ![1, 2].contains(&q.update.operation)
                || q.update.identity != q.key.identity
                || q.handle == [0; 32]
                || q.update.new_key != encode(&q.key)?
            {
                return Err(Error("stage-key"));
            }
            if q.authorizations.owner.len() != 1
                || !q.authorizations.possession.is_empty()
                || !q.authorizations.governance.is_empty()
            {
                return Err(Error("stage-authorizations"));
            }
            permit_shape(&q.permit, 4, q.fence, &object_id("update", &q.update)?)?;
            if q.permit.body.identity != q.update.identity {
                return Err(Error("permit-association"));
            }
        }
        5 => {
            sign_template(&decode(raw)?)?;
        }
        7 => {
            let q = decode::<RetireRequest>(raw)?;
            if ![3, 7].contains(&q.update.operation)
                || q.key_id == [0; 32]
                || (q.update.operation == 3 && q.key_id != q.update.old_key)
            {
                return Err(Error("retire-key"));
            }
            if !q.authorizations.owner.is_empty()
                || !q.authorizations.possession.is_empty()
                || q.authorizations.administration.len() != 1
                || !q.authorizations.governance.is_empty()
            {
                return Err(Error("retire-authorizations"));
            }
            permit_shape(&q.permit, 7, q.fence, &object_id("update", &q.update)?)?;
            if q.permit.body.identity != q.update.identity {
                return Err(Error("permit-association"));
            }
        }
        10 => {
            let q = decode::<GetRegistryRequest>(raw)?;
            let id = registry_query_id(&q.anchor, q.limit)?;
            if let Some(c) = q.cursor.first() {
                if c.anchor != q.anchor || c.query_id != id || c.last_identity == [0; 32] {
                    return Err(Error("cursor-binding"));
                }
            }
        }
        _ => {}
    }
    if method >= 8 {
        anchor(&anchor_prefix(raw)?)?;
    }
    Ok(())
}
pub fn api_request_id(method: u8, raw: &[u8]) -> Result<Hash, Error> {
    validate_api_binary(method, false, false, raw)?;
    match method {
        1 => Ok([0; 32]),
        5 => Ok(decode::<SignRequest>(raw)?.request_id),
        6 => Ok(decode::<ResultRequest>(raw)?.request_id),
        _ => {
            let mut bytes = vec![method];
            bytes.extend_from_slice(raw);
            digest("api-request", &bytes)
        }
    }
}
pub fn registry_query_id(a: &Anchor, limit: u8) -> Result<Hash, Error> {
    anchor(a)?;
    if !(1..=128).contains(&limit) {
        return Err(Error("page-limit"));
    }
    let mut bytes = encode(a)?;
    bytes.push(limit);
    digest("registry-query", &bytes)
}
pub fn validate_api_request<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    method: u8,
    raw: &[u8],
    reader: &mut ObjectReader<F>,
) -> Result<(), Error> {
    scalar_request(method, raw)?;
    match method {
        13 => {
            let q = decode::<VerifyCertificateRequest>(raw)?;
            let cert = certificate(&q.certificate, reader)?;
            proof_shape(&q.committee, &q.anchor, 5, &cert.duty.committee, reader)?;
            proof_shape(&q.policy, &q.anchor, 2, &cert.duty.policy, reader)?;
        }
        14 => {
            let q = decode::<ChunkRequest>(raw)?;
            validate_manifest(&q.manifest)?;
            if usize::from(q.index) >= q.manifest.chunk_hashes.len() {
                return Err(Error("chunk-index"));
            }
        }
        15 => {
            let q = decode::<PutChunkRequest>(raw)?;
            validate_chunk(&q.manifest, q.index, &q.data)?;
        }
        _ => {}
    }
    Ok(())
}
// Structural association only; successful parsing never supplies chain or
// service authority. Native proofs, signatures and witnessed receipts follow.
pub fn validate_api_response<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
    method: u8,
    request: &[u8],
    response: &[u8],
    reader: &mut ObjectReader<F>,
) -> Result<(), Error> {
    scalar_request(method, request)?;
    validate_api_binary(method, true, false, response)?;
    if method >= 8 && anchor_prefix(request)? != anchor_prefix(response)? {
        return Err(Error("response-anchor"));
    }
    match method {
        1 => {
            let r = decode::<Capabilities>(response)?;
            if r.interface_digest != INTERFACE_FINGERPRINT {
                return Err(Error("interface-digest"));
            }
            if r.persistent_journal > 1
                || r.fencing > 1
                || r.stateful > 1
                || r.max_request == 0
                || r.max_request > 2_000_000
                || r.max_result == 0
                || r.max_result > 2_000_000
            {
                return Err(Error("capability-bounds"));
            }
            if !suites(&r.installed)
                || !suites(&r.admitted)
                || r.admitted.iter().any(|s| !r.installed.contains(s))
            {
                return Err(Error("capability-profiles"));
            }
        }
        2 => {
            let q = decode::<PublicRequest>(request)?;
            let r = decode::<Key>(response)?;
            if object_id("key", &r)? != q.key_id {
                return Err(Error("response-key"));
            }
        }
        3 => {
            let q = decode::<PrepareRequest>(request)?;
            let r = decode::<PrepareResult>(response)?;
            let k = &r.prepared.key;
            if k.identity != q.identity
                || k.role != q.role
                || k.suite != q.suite
                || k.parameters != q.parameters
                || k.epoch != q.epoch
                || k.valid_from != q.valid_from
                || k.valid_until != q.valid_until
                || r.prepared.handle == [0; 32]
            {
                return Err(Error("prepared-binding"));
            }
            receipt(
                &r.receipt,
                request,
                &PrepareResultBody { prepared: r.prepared },
                ReceiptLink {
                    method,
                    fence: q.fence,
                    subject: digest("api-subject", request)?,
                    context: [0; 32],
                },
            )?;
        }
        4 => {
            let q = decode::<StageRequest>(request)?;
            let r = decode::<StageResult>(response)?;
            if r.key != q.key
                || r.possession.key != key_reference(&q.key)?
                || r.possession.update_id != object_id("update", &q.update)?
                || r.possession.signature.is_empty()
                || (q.key.suite == 1 && q.key.parameters == 1 && r.possession.signature.len() != 64)
            {
                return Err(Error("staged-binding"));
            }
            receipt(
                &r.receipt,
                request,
                &StageResultBody { key: r.key, possession: r.possession },
                ReceiptLink {
                    method,
                    fence: q.fence,
                    subject: digest("api-subject", request)?,
                    context: object_id("permit", &q.permit)?,
                },
            )?;
        }
        5 => {
            let q = decode::<SignRequest>(request)?;
            let r = decode::<SignResult>(response)?;
            let e = sign_template(&q)?;
            let statement = signing_statement(&e.duty, &e.record)?;
            let subject = digest("statement", &statement)?;
            if r.request_id != q.request_id
                || r.statement_id != subject
                || r.fence != q.fence
                || statement != signing_statement(&e.duty, &r.record)?
            {
                return Err(Error("sign-result-binding"));
            }
            for c in &r.record.components {
                if c.signature.is_empty()
                    || (c.suite == 1 && c.parameters == 1 && c.signature.len() != 64)
                {
                    return Err(Error("sign-result-signatures"));
                }
            }
            receipt(
                &r.receipt,
                request,
                &SignResultBody {
                    request_id: r.request_id,
                    statement_id: r.statement_id,
                    record: r.record,
                    fence: r.fence,
                },
                ReceiptLink {
                    method,
                    fence: q.fence,
                    subject,
                    context: object_id("permit", &q.permit)?,
                },
            )?;
        }
        6 => {
            validate_request_state(
                &decode(response)?,
                &decode::<ResultRequest>(request)?.request_id,
            )?;
        }
        7 => {
            let q = decode::<RetireRequest>(request)?;
            let r = decode::<RetireResult>(response)?;
            if r.key_id != q.key_id || r.update_id != object_id("update", &q.update)? {
                return Err(Error("retirement-binding"));
            }
            receipt(
                &r.receipt,
                request,
                &RetireResultBody { key_id: r.key_id, update_id: r.update_id },
                ReceiptLink {
                    method,
                    fence: q.fence,
                    subject: digest("api-subject", request)?,
                    context: object_id("permit", &q.permit)?,
                },
            )?;
        }
        8 => {
            let q = decode::<GetProfileRequest>(request)?;
            let r = decode::<ProfileResult>(response)?;
            if r.interface_digest != INTERFACE_FINGERPRINT {
                return Err(Error("interface-digest"));
            }
            if r.can_parse > 1 || r.can_verify > 1 || r.can_verify > r.can_parse {
                return Err(Error("profile-flags"));
            }
            if !suites(&r.installed) || !suites(&r.active) {
                return Err(Error("profile-suites"));
            }
            proof_shape(
                &r.proof,
                &q.anchor,
                6,
                &object_id(
                    "profile_state",
                    &ProfileState {
                        interface_digest: r.interface_digest,
                        policy: r.policy,
                        active: r.active,
                    },
                )?,
                reader,
            )?;
        }
        9 => {
            let q = decode::<GetPolicyRequest>(request)?;
            let r = decode::<PolicyResult>(response)?;
            if object_id("policy", &r.policy)? != q.policy_id {
                return Err(Error("response-policy"));
            }
            proof_shape(&r.proof, &q.anchor, 2, &q.policy_id, reader)?;
        }
        10 => {
            let q = decode::<GetRegistryRequest>(request)?;
            let r = decode::<RegistryResult>(response)?;
            let qid = registry_query_id(&q.anchor, q.limit)?;
            if r.query_id != qid {
                return Err(Error("page-query"));
            }
            if r.identities.len() > usize::from(q.limit) {
                return Err(Error("page-order"));
            }
            let start = q.cursor.first().map_or([0; 32], |c| c.last_identity);
            let mut last = start;
            for identity in &r.identities {
                if identity.identity <= last {
                    return Err(Error("page-order"));
                }
                last = identity.identity;
            }
            if let Some(c) = r.cursor.first() {
                if r.identities.is_empty()
                    || c.last_identity != last
                    || c.anchor != q.anchor
                    || c.query_id != qid
                {
                    return Err(Error("page-cursor"));
                }
            }
            let mut raw = qid.to_vec();
            raw.extend_from_slice(&start);
            raw.push(u8::try_from(r.identities.len()).map_err(|_| Error("page-order"))?);
            for identity in &r.identities {
                raw.extend_from_slice(&encode(identity)?);
            }
            raw.push(u8::try_from(r.cursor.len()).map_err(|_| Error("page-cursor"))?);
            for c in &r.cursor {
                raw.extend_from_slice(&encode(c)?);
            }
            proof_shape(&r.proof, &q.anchor, 3, &digest("registry-page", &raw)?, reader)?;
        }
        11 => {
            let q = decode::<GetKeyRequest>(request)?;
            let r = decode::<KeyResult>(response)?;
            if object_id("key", &r.key)? != q.key_id {
                return Err(Error("response-key"));
            }
            proof_shape(&r.proof, &q.anchor, 4, &q.key_id, reader)?;
        }
        12 => {
            let q = decode::<GetCertificateRequest>(request)?;
            let r = decode::<CertificateResult>(response)?;
            if r.era != 1 || r.interface_digest != INTERFACE_FINGERPRINT {
                return Err(Error("certificate-era"));
            }
            let cert = certificate(&r.certificate, reader)?;
            if object_id("certificate", &cert)? != q.certificate_id {
                return Err(Error("certificate-id"));
            }
            proof_shape(&r.committee, &q.anchor, 5, &cert.duty.committee, reader)?;
            proof_shape(&r.policy, &q.anchor, 2, &cert.duty.policy, reader)?;
        }
        13 => {
            let q = decode::<VerifyCertificateRequest>(request)?;
            let r = decode::<VerifyResult>(response)?;
            let cert = certificate(&q.certificate, reader)?;
            if r.certificate_id != object_id("certificate", &cert)?
                || r.policy != cert.duty.policy
                || r.committee != cert.duty.committee
                || r.duty != object_id("duty", &cert.duty)?
            {
                return Err(Error("verified-binding"));
            }
            let mut signers = Vec::new();
            let mut previous = [0; 32];
            for row in &cert.records {
                if row.identity <= previous {
                    return Err(Error("verified-signer-order"));
                }
                signers.push(row.identity);
                previous = row.identity;
            }
            if signers.is_empty() {
                return Err(Error("verified-signer-order"));
            }
            if r.signers != signers || r.weight == 0 || r.weight > MAX_WEIGHT {
                return Err(Error("verified-signers"));
            }
            proof_shape(&q.committee, &q.anchor, 5, &r.committee, reader)?;
            proof_shape(&q.policy, &q.anchor, 2, &r.policy, reader)?;
        }
        14 => {
            let q = decode::<ChunkRequest>(request)?;
            let r = decode::<ChunkResult>(response)?;
            if r.manifest_id != object_id("object_ref", &q.manifest)? || r.index != q.index {
                return Err(Error("chunk-correlation"));
            }
            validate_chunk(&q.manifest, r.index, &r.data)?;
        }
        15 => {
            let q = decode::<PutChunkRequest>(request)?;
            let r = decode::<PutChunkResult>(response)?;
            if r.manifest_id != object_id("object_ref", &q.manifest)? || r.index != q.index {
                return Err(Error("chunk-correlation"));
            }
            validate_chunk(&q.manifest, q.index, &q.data)?;
        }
        _ => return Err(Error("method")),
    }
    Ok(())
}
