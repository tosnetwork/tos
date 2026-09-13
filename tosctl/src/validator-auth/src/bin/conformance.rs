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
