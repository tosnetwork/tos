use std::{cell::RefCell, collections::BTreeMap, env, fs, path::PathBuf, rc::Rc};
use tos_validator_auth::{
    api_routes::API_ROUTES,
    api_semantics::api_request_id,
    client::{
        CheckedOutcome, Client, HttpRequest, HttpResponse, ResponseVerifier, Transport, MEDIA_TYPE,
    },
    codec::{decode, encode, Error, Hash},
    crypto::object_id,
    transfer::{ObjectReader, CHUNK_BYTES},
    transport::{decode_transport_frame, encode_transport_frame, TransportFrame},
    types::*,
};
use tos_validator_auth_native::{
    certificate_proof::NativeCertificateVerifier, committee::ChainContext,
};
fn check(ok: bool, label: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(label.to_owned())
    }
}
fn hex(id: &Hash) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Default)]
struct Calls {
    main: usize,
    chunks: BTreeMap<(Hash, u8), usize>,
}
struct FixtureTransport {
    method: u8,
    response: Vec<u8>,
    objects: PathBuf,
    calls: Rc<RefCell<Calls>>,
}
impl Transport for FixtureTransport {
    fn exchange(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        let route =
            API_ROUTES.iter().find(|r| r.path == request.path).ok_or(Error("fixture-route"))?;
        let frame = decode_transport_frame(request.body.as_bytes(), route.method, false, None)?;
        let raw = if route.method == 14 {
            let q = decode::<ChunkRequest>(&frame.payload)?;
            *self.calls.borrow_mut().chunks.entry((q.manifest.object_id, q.index)).or_default() +=
                1;
            let bytes = fs::read(self.objects.join(hex(&q.manifest.object_id)))
                .map_err(|_| Error("fixture-object"))?;
            let offset = usize::from(q.index) * CHUNK_BYTES;
            let data = bytes
                .get(offset..bytes.len().min(offset + CHUNK_BYTES))
                .ok_or(Error("fixture-chunk"))?
                .to_vec();
            encode(&ChunkResult {
                anchor: q.anchor,
                manifest_id: object_id("object_ref", &q.manifest)?,
                index: q.index,
                data,
            })?
        } else {
            if route.method != self.method {
                return Err(Error("fixture-method"));
            }
            self.calls.borrow_mut().main += 1;
            self.response.clone()
        };
        Ok(HttpResponse {
            status: 200,
            content_type: MEDIA_TYPE.to_owned(),
            body: encode_transport_frame(&TransportFrame {
                method: route.method,
                request_id: frame.request_id,
                payload: raw,
                response: true,
                error: false,
            })?,
        })
    }
}
#[cfg(unix)]
fn http(args: &[String]) -> Result<(), String> {
    use tos_validator_auth::unix_http::UnixHttp;
    let prefix = &args[7];
    let read = |suffix: &str| fs::read(format!("{prefix}.{suffix}")).map_err(|e| e.to_string());
    let raw = read("chain")?;
    check(raw.len() == 100, "chain-length")?;
    let verifier = NativeCertificateVerifier {
        anchor: decode::<Anchor>(&read("anchor")?).map_err(|e| e.0.to_owned())?,
        expected: decode::<Duty>(&read("expected")?).map_err(|e| e.0.to_owned())?,
        chain: ChainContext {
            network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| "network")?),
            genesis_root: raw[4..36].try_into().map_err(|_| "genesis")?,
            genesis_file: raw[36..68].try_into().map_err(|_| "genesis")?,
            chain_domain: raw[68..100].try_into().map_err(|_| "domain")?,
        },
    };
    let client =
        Client::new(UnixHttp::new(PathBuf::from(&args[2]), args[3].parse().map_err(|_| "uid")?));
    let request = fs::read(&args[5]).map_err(|e| e.to_string())?;
    let method = args[4].parse().map_err(|_| "method")?;
    let checked = client.call_verified(method, &request, &verifier).map_err(|e| e.0.to_owned())?;
    match checked {
        CheckedOutcome::Result(result) => {
            let bytes = encode(&result.result().map_err(|e| e.0.to_owned())?)
                .map_err(|e| e.0.to_owned())?;
            fs::write(&args[6], bytes).map_err(|e| e.to_string())
        }
        CheckedOutcome::Error(error) => Err(format!("api-error:{}", error.code)),
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    #[cfg(unix)]
    if args.len() == 8 && args[1] == "http" {
        return http(&args);
    }
    check(args.len() == 2, "arguments")?;
    let path = PathBuf::from(&args[1]);
    let count: usize = fs::read_to_string(path.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "count")?;
    check(count >= 55, "complete-corpus")?;
    for i in 0..count {
        let read =
            |suffix: &str| fs::read(path.join(format!("{i}.{suffix}"))).map_err(|e| e.to_string());
        let meta = String::from_utf8(read("case")?).map_err(|_| "metadata")?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        check(fields.len() == 4, "fields")?;
        let method: u8 = fields[0].parse().map_err(|_| "method")?;
        let accepted = fields[1] == "1";
        let anchor = decode::<Anchor>(&read("anchor")?).map_err(|e| e.0.to_owned())?;
        let expected = decode::<Duty>(&read("expected")?).map_err(|e| e.0.to_owned())?;
        let raw = read("chain")?;
        check(raw.len() == 100, "chain-length")?;
        let chain = ChainContext {
            network: i32::from_be_bytes(raw[..4].try_into().map_err(|_| "network")?),
            genesis_root: raw[4..36].try_into().map_err(|_| "genesis")?,
            genesis_file: raw[36..68].try_into().map_err(|_| "genesis")?,
            chain_domain: raw[68..100].try_into().map_err(|_| "domain")?,
        };
        let verifier = NativeCertificateVerifier { anchor, chain, expected };
        let request = read("request")?;
        let response = read("response")?;
        let calls = Rc::new(RefCell::new(Calls::default()));
        let client = Client::new(FixtureTransport {
            method,
            response: response.clone(),
            objects: path.join("objects"),
            calls: calls.clone(),
        });
        let result = client.call_verified(method, &request, &verifier);
        let success = matches!(result, Ok(CheckedOutcome::Result(_)));
        check(
            success == accepted,
            &format!("{}: {}", fields[2], if success { "accepted" } else { "refused" }),
        )?;
        if let Ok(CheckedOutcome::Result(verified)) = result {
            let actual = verified.result().map_err(|e| e.0.to_owned())?;
            check(
                encode(&actual).map_err(|e| e.0.to_owned())? == read("verified")?,
                "client-native-values",
            )?;
            check(calls.borrow().main == 1, "client-exact-call")?;
        }
        check(calls.borrow().chunks.values().all(|n| *n == 1), "client-proof-chunks-once")?;
        if fields[2] == "native-signature-refusal"
            || fields[2] == "committee-proof-authentication"
            || fields[2] == "policy-proof-authentication"
        {
            check(calls.borrow().main == 0, "native-request-admission")?;
        }
        if method == 13 && accepted && i == 1 {
            let fetch = |object: &ObjectRef, n: u8| {
                let bytes = fs::read(path.join("objects").join(hex(&object.object_id)))
                    .map_err(|_| Error("fixture-object"))?;
                let offset = usize::from(n) * CHUNK_BYTES;
                Ok(bytes
                    .get(offset..bytes.len().min(offset + CHUNK_BYTES))
                    .ok_or(Error("fixture-chunk"))?
                    .to_vec())
            };
            let id = api_request_id(13, &request).map_err(|e| e.0.to_owned())?;
            let mut changed =
                decode::<VerifyCertificateRequest>(&request).map_err(|e| e.0.to_owned())?;
            changed.policy.proof_hash[0] ^= 1;
            let changed = encode(&changed).map_err(|e| e.0.to_owned())?;
            let changed_id = api_request_id(13, &changed).map_err(|e| e.0.to_owned())?;
            for (label, bytes, identity) in [
                ("prepared-request-rebinding", changed.as_slice(), changed_id),
                ("prepared-bytes-binding", changed.as_slice(), id),
            ] {
                let mut reader = ObjectReader::new(fetch);
                let prepared =
                    verifier.prepare(13, &request, &mut reader).map_err(|e| e.0.to_owned())?;
                check(
                    verifier.verify(prepared, 13, identity, bytes, &response, &mut reader).is_err(),
                    label,
                )?;
            }
            for field in 0..3 {
                let mut other = NativeCertificateVerifier {
                    anchor: verifier.anchor.clone(),
                    chain: verifier.chain.clone(),
                    expected: verifier.expected.clone(),
                };
                let label = match field {
                    0 => {
                        other.anchor.file[0] ^= 1;
                        "prepared-anchor-binding"
                    }
                    1 => {
                        other.chain.chain_domain[0] ^= 1;
                        "prepared-chain-binding"
                    }
                    _ => {
                        other.expected.session[0] ^= 1;
                        "prepared-duty-binding"
                    }
                };
                let mut reader = ObjectReader::new(fetch);
                let prepared =
                    verifier.prepare(13, &request, &mut reader).map_err(|e| e.0.to_owned())?;
                check(
                    other.verify(prepared, 13, id, &request, &response, &mut reader).is_err(),
                    label,
                )?;
            }
        }
    }
    println!("PASS: native certificate client {count} cases, single proof fetches and prepared-context binding");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
