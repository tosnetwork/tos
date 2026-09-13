use std::{env, fs};
use tos_validator_auth::{
    codec::{decode, encode, Error, Wire},
    crypto::AdmittedKey,
    types::*,
};
fn roundtrip<T: Wire>(input: &[u8], out: &str) -> Result<(), Error> {
    fs::write(out, encode(&decode::<T>(input)?)?).map_err(|_| Error("write"))
}
fn run() -> Result<(), Error> {
    let a: Vec<String> = env::args().collect();
    if a.len() >= 7 && (a[1] == "apply" || a[1] == "due" || a[1] == "select") {
        return lifecycle_probe(&a);
    }

    if a.len() == 4 && a[1] == "service" {
        return service_probe(&a[2], &a[3]);
    }

    if a.len() == 6 && a[1].parse::<u8>().is_ok() {
        let method = a[1].parse::<u8>().map_err(|_| Error("method"))?;
        let request = fs::read(&a[3]).map_err(|_| Error("fixture-file"))?;
        let response = fs::read(&a[4]).map_err(|_| Error("fixture-file"))?;
        let mut reader =
            tos_validator_auth::transfer::ObjectReader::new(|reference: &ObjectRef, index: u8| {
                let id: String = reference.object_id.iter().map(|b| format!("{b:02x}")).collect();
                use std::io::{Read, Seek, SeekFrom};
                let mut file = fs::File::open(std::path::Path::new(&a[5]).join(id))
                    .map_err(|_| Error("fixture-file"))?;
                let length = file.metadata().map_err(|_| Error("fixture-file"))?.len();
                let offset = u64::from(index) * tos_validator_auth::transfer::CHUNK_BYTES as u64;
                let remaining = length.checked_sub(offset).ok_or(Error("fixture-chunk"))?;
                let size = remaining.min(tos_validator_auth::transfer::CHUNK_BYTES as u64) as usize;
                let mut bytes = vec![0; size];
                file.seek(SeekFrom::Start(offset)).map_err(|_| Error("fixture-file"))?;
                file.read_exact(&mut bytes).map_err(|_| Error("fixture-file"))?;
                Ok(bytes)
            });
        return if a[2] == "request" {
            tos_validator_auth::api_semantics::validate_api_request(method, &request, &mut reader)
        } else {
            tos_validator_auth::api_semantics::validate_api_response(
                method,
                &request,
                &response,
                &mut reader,
            )
        };
    }
    if a.len() == 5 && a[1].parse::<u8>().is_ok() {
        let method = a[1].parse::<u8>().map_err(|_| Error("method"))?;
        let frame = tos_validator_auth::transport::decode_transport_frame(
            &fs::read(&a[3]).map_err(|_| Error("read"))?,
            method,
            a[2] == "response",
            None,
        )?;
        fs::write(&a[4], tos_validator_auth::transport::encode_transport_frame(&frame)?)
            .map_err(|_| Error("write"))?;
        return Ok(());
    }
    if a.len() == 7 && a[1] == "certificate" {
        let policy = decode::<Policy>(&fs::read(&a[2]).map_err(|_| Error("read"))?)?;
        let committee = decode::<Committee>(&fs::read(&a[3]).map_err(|_| Error("read"))?)?;
        let cert = decode::<Certificate>(&fs::read(&a[4]).map_err(|_| Error("read"))?)?;
        let expected = decode::<Duty>(&fs::read(&a[5]).map_err(|_| Error("read"))?)?;
        let snapshot = tos_validator_auth::verify::RegistrySnapshot::compile(&committee, &policy)?;
        let verified = snapshot.verify_certificate(&cert, &expected)?;
        fs::write(&a[6], verified.weight().to_string()).map_err(|_| Error("write"))?;
        return Ok(());
    }
    if a.len() == 6 && a[1] == "verify" {
        let key = AdmittedKey::admit(&fs::read(&a[2]).map_err(|_| Error("read"))?)?;
        if !key.verify(
            &fs::read(&a[3]).map_err(|_| Error("read"))?,
            &fs::read(&a[4]).map_err(|_| Error("read"))?,
        ) {
            return Err(Error("signature"));
        }
        return Ok(());
    }
    if a.len() == 3 && a[1] == "admit" {
        AdmittedKey::admit(&fs::read(&a[2]).map_err(|_| Error("read"))?)?;
        return Ok(());
    }
    if a.len() != 5 || a[1] != "codec" {
        return Err(Error("arguments"));
    }
    let bytes = fs::read(&a[3]).map_err(|_| Error("read"))?;
    dispatch(&a[2], &bytes, &a[4])
}
include!("dispatch.inc");
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e.0);
        std::process::exit(1);
    }
}

include!("service_probe.inc");

include!("lifecycle_probe.inc");
