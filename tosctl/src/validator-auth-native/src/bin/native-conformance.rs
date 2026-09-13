use std::{env, fs};
use tos_validator_auth::codec::Error;
use tos_validator_auth_native::cells;
fn run() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    #[cfg(unix)]
    if args.len() == 9 && args[1] == "http" {
        use tos_validator_auth::{
            client::{CheckedOutcome, Client},
            codec::{decode, encode},
            types::Anchor,
            unix_http::UnixHttp,
        };
        let client = Client::new(UnixHttp::new(
            std::path::PathBuf::from(&args[2]),
            args[3].parse().map_err(|_| Error("uid"))?,
        ));
        let request = fs::read(&args[5]).map_err(|_| Error("fixture-file"))?;
        let anchor = decode::<Anchor>(&fs::read(&args[6]).map_err(|_| Error("fixture-file"))?)?;
        let verifier = tos_validator_auth_native::proof::NativeStateVerifier {
            anchor,
            network: args[7].parse().map_err(|_| Error("network"))?,
        };
        match client.call_verified(
            args[4].parse().map_err(|_| Error("method"))?,
            &request,
            &verifier,
        )? {
            CheckedOutcome::Result(result) => {
                return fs::write(&args[8], result.bytes()).map_err(|_| Error("fixture-file"))
            }
            CheckedOutcome::Error(error) => {
                fs::write(&args[8], encode(&error)?).map_err(|_| Error("fixture-file"))?;
                return Err(Error("api-error"));
            }
        }
    }
    if args.len() == 9 && args[1] == "proof" {
        use tos_validator_auth::{
            codec::decode,
            transfer::ObjectReader,
            types::{Anchor, ObjectRef},
        };
        let request = fs::read(&args[4]).map_err(|_| Error("fixture-file"))?;
        let response = fs::read(&args[5]).map_err(|_| Error("fixture-file"))?;
        let anchor = decode::<Anchor>(&fs::read(&args[6]).map_err(|_| Error("fixture-file"))?)?;
        let mut reader = ObjectReader::new(|object: &ObjectRef, index: u8| {
            let name: String = object.object_id.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::path::Path::new(&args[7]).join(name);
            if fs::metadata(&path).map_err(|_| Error("fixture-file"))?.len() > cells::MAX_BOC as u64
            {
                return Err(Error("fixture-bound"));
            }
            let data = fs::read(path).map_err(|_| Error("fixture-file"))?;
            let begin = usize::from(index) * 1_048_576;
            let part =
                data.get(begin..data.len().min(begin + 1_048_576)).ok_or(Error("fixture-index"))?;
            Ok(part.to_vec())
        });
        use tos_validator_auth::client::ResponseVerifier;
        let method = args[2].parse().map_err(|_| Error("method"))?;
        let verifier = tos_validator_auth_native::proof::NativeStateVerifier {
            anchor,
            network: args[3].parse().map_err(|_| Error("network"))?,
        };
        verifier.prepare(method, &request, &mut reader)?;
        let verified = verifier.verify(
            (),
            method,
            tos_validator_auth::api_semantics::api_request_id(method, &request)?,
            &request,
            &response,
            &mut reader,
        )?;
        return fs::write(&args[8], verified.bytes()).map_err(|_| Error("fixture-file"));
    }
    if args.len() != 4 && args.len() != 5 {
        return Err(Error("arguments"));
    }
    let input = fs::read(&args[2]).map_err(|_| Error("fixture-file"))?;
    let result = match args[1].as_str() {
        "pack" => cells::serialize_bytes(&input)?,
        "unpack" => cells::deserialize_bytes(
            &input,
            if args.len() == 5 {
                args[4].parse().map_err(|_| Error("budget"))?
            } else {
                cells::MAX_OBJECT
            },
        )?,
        _ => return Err(Error("arguments")),
    };
    fs::write(&args[3], result).map_err(|_| Error("fixture-file"))
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error.0);
        std::process::exit(1);
    }
}
