// Generated from the frozen method table.
use crate::{
    codec::{decode, Error},
    types::*,
};
pub fn validate_api_binary(
    method: u8,
    response: bool,
    error: bool,
    raw: &[u8],
) -> Result<(), Error> {
    if !(1..=15).contains(&method) {
        return Err(Error("method"));
    }
    if raw.len() > 2_000_000 {
        return Err(Error("api-binary-bound"));
    }
    if error {
        decode::<ApiError>(raw)?;
        return Ok(());
    }
    match method {
        1 => {
            if response {
                decode::<Capabilities>(raw)?;
            } else {
                decode::<CapabilitiesRequest>(raw)?;
            }
        }
        2 => {
            if response {
                decode::<Key>(raw)?;
            } else {
                decode::<PublicRequest>(raw)?;
            }
        }
        3 => {
            if response {
                decode::<PrepareResult>(raw)?;
            } else {
                decode::<PrepareRequest>(raw)?;
            }
        }
        4 => {
            if response {
                decode::<StageResult>(raw)?;
            } else {
                decode::<StageRequest>(raw)?;
            }
        }
        5 => {
            if response {
                decode::<SignResult>(raw)?;
            } else {
                decode::<SignRequest>(raw)?;
            }
        }
        6 => {
            if response {
                decode::<RequestState>(raw)?;
            } else {
                decode::<ResultRequest>(raw)?;
            }
        }
        7 => {
            if response {
                decode::<RetireResult>(raw)?;
            } else {
                decode::<RetireRequest>(raw)?;
            }
        }
        8 => {
            if response {
                decode::<ProfileResult>(raw)?;
            } else {
                decode::<GetProfileRequest>(raw)?;
            }
        }
        9 => {
            if response {
                decode::<PolicyResult>(raw)?;
            } else {
                decode::<GetPolicyRequest>(raw)?;
            }
        }
        10 => {
            if response {
                decode::<RegistryResult>(raw)?;
            } else {
                decode::<GetRegistryRequest>(raw)?;
            }
        }
        11 => {
            if response {
                decode::<KeyResult>(raw)?;
            } else {
                decode::<GetKeyRequest>(raw)?;
            }
        }
        12 => {
            if response {
                decode::<CertificateResult>(raw)?;
            } else {
                decode::<GetCertificateRequest>(raw)?;
            }
        }
        13 => {
            if response {
                decode::<VerifyResult>(raw)?;
            } else {
                decode::<VerifyCertificateRequest>(raw)?;
            }
        }
        14 => {
            if response {
                decode::<ChunkResult>(raw)?;
            } else {
                decode::<ChunkRequest>(raw)?;
            }
        }
        15 => {
            if response {
                decode::<PutChunkResult>(raw)?;
            } else {
                decode::<PutChunkRequest>(raw)?;
            }
        }
        _ => return Err(Error("method")),
    }
    Ok(())
}
