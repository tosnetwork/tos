use crate::{
    api_routes::API_ROUTES,
    api_semantics::{api_request_id, validate_api_request, validate_api_response},
    codec::{decode, encode, Error, Hash, Wire},
    transfer::ObjectReader,
    transport::{decode_transport_frame, encode_transport_frame, TransportFrame},
    types::*,
};
pub const MEDIA_TYPE: &str = "application/vnd.tos.validator-auth.v1+json";
pub struct HttpRequest {
    pub verb: &'static str,
    pub path: &'static str,
    pub content_type: &'static str,
    pub body: String,
}
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}
/// Implementations authenticate the remote principal and enforce bounded I/O.
/// A call performs one invocation. No transport error implies retry permission.
pub trait Transport {
    fn exchange(&self, request: &HttpRequest) -> Result<HttpResponse, Error>;
}
/// Framing and request/result association do not establish chain authority.
/// Native proofs and independent receipt trust must be verified by the caller.
pub struct UntrustedResult {
    pub method: u8,
    pub request_id: Hash,
    pub bytes: Vec<u8>,
}
pub enum CheckedOutcome<R> {
    Result(R),
    Error(ApiError),
}
pub type Outcome = CheckedOutcome<UntrustedResult>;
/// Admission owns the result type. Native verifiers can return a private
/// verified type while sharing this call's framing and attachment budget.
pub trait ResponseVerifier {
    type Output;
    fn verify<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
        &self,
        method: u8,
        id: Hash,
        request: &[u8],
        response: &[u8],
        reader: &mut ObjectReader<F>,
    ) -> Result<Self::Output, Error>;
}
struct SemanticVerifier;
impl ResponseVerifier for SemanticVerifier {
    type Output = UntrustedResult;
    fn verify<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>>(
        &self,
        method: u8,
        id: Hash,
        request: &[u8],
        response: &[u8],
        reader: &mut ObjectReader<F>,
    ) -> Result<UntrustedResult, Error> {
        validate_api_response(method, request, response, reader)?;
        Ok(UntrustedResult { method, request_id: id, bytes: response.to_vec() })
    }
}
pub struct Client<T> {
    transport: T,
}
impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
    fn chunk(&self, anchor: &Anchor, manifest: &ObjectRef, index: u8) -> Result<Vec<u8>, Error> {
        let request = ChunkRequest { anchor: anchor.clone(), manifest: manifest.clone(), index };
        match self.call(14, &encode(&request)?)? {
            Outcome::Result(result) => Ok(decode::<ChunkResult>(&result.bytes)?.data),
            Outcome::Error(_) => Err(Error("attachment-unavailable")),
        }
    }
    pub fn call(&self, method: u8, request: &[u8]) -> Result<Outcome, Error> {
        self.call_verified(method, request, &SemanticVerifier)
    }
    pub fn call_verified<V: ResponseVerifier>(
        &self,
        method: u8,
        request: &[u8],
        verifier: &V,
    ) -> Result<CheckedOutcome<V::Output>, Error> {
        let route =
            API_ROUTES.iter().find(|route| route.method == method).ok_or(Error("method"))?;
        let anchor = request_anchor(method, request)?;
        let mut reader = ObjectReader::new(|manifest: &ObjectRef, index| {
            self.chunk(anchor.as_ref().ok_or(Error("attachment-anchor"))?, manifest, index)
        });
        validate_api_request(method, request, &mut reader)?;
        let id = api_request_id(method, request)?;
        let frame = TransportFrame {
            method,
            request_id: id,
            payload: request.to_vec(),
            response: false,
            error: false,
        };
        let body = if method == 1 { String::new() } else { encode_transport_frame(&frame)? };
        let response = self.transport.exchange(&HttpRequest {
            verb: route.verb,
            path: route.path,
            content_type: MEDIA_TYPE,
            body,
        })?;
        if response.content_type != MEDIA_TYPE || !matches!(response.status, 200 | 400 | 403) {
            return Err(Error("http-response-contract"));
        }
        let result = decode_transport_frame(response.body.as_bytes(), method, true, Some(&id))?;
        if result.error {
            return Ok(CheckedOutcome::Error(decode::<ApiError>(&result.payload)?));
        }
        if response.status != 200 {
            return Err(Error("http-success-status"));
        }
        // Response validation shares the operation's attachment budget. It may
        // refuse an oversized combined request/response, never truncate proof.
        Ok(CheckedOutcome::Result(verifier.verify(
            method,
            id,
            request,
            &result.payload,
            &mut reader,
        )?))
    }
    pub fn typed<Q: Wire>(&self, method: u8, request: &Q) -> Result<Outcome, Error> {
        self.call(method, &encode(request)?)
    }
}
fn request_anchor(method: u8, raw: &[u8]) -> Result<Option<Anchor>, Error> {
    Ok(match method {
        4 => Some(decode::<StageRequest>(raw)?.permit.body.anchor),
        5 => Some(decode::<SignRequest>(raw)?.permit.body.anchor),
        7 => Some(decode::<RetireRequest>(raw)?.permit.body.anchor),
        8 => Some(decode::<GetProfileRequest>(raw)?.anchor),
        9 => Some(decode::<GetPolicyRequest>(raw)?.anchor),
        10 => Some(decode::<GetRegistryRequest>(raw)?.anchor),
        11 => Some(decode::<GetKeyRequest>(raw)?.anchor),
        12 => Some(decode::<GetCertificateRequest>(raw)?.anchor),
        13 => Some(decode::<VerifyCertificateRequest>(raw)?.anchor),
        14 => Some(decode::<ChunkRequest>(raw)?.anchor),
        15 => Some(decode::<PutChunkRequest>(raw)?.anchor),
        1..=3 | 6 => None,
        _ => return Err(Error("method")),
    })
}
