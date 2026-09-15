fn object_store_probe(input: &str, output: &str) -> Result<(), Error> {
    use tos_validator_auth::{
        codec::Hash,
        crypto::digest,
        transfer::{object_value, ScopedObjectStore, CHUNK_BYTES},
    };

    fn number<T: std::str::FromStr>(
        fields: &mut std::str::SplitWhitespace<'_>,
    ) -> Result<T, Error> {
        fields
            .next()
            .ok_or(Error("script"))?
            .parse::<T>()
            .map_err(|_| Error("script"))
    }

    fn hash(value: u32) -> Hash {
        let mut out = [0u8; 32];
        out[28..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn anchor(seqno: u32) -> Anchor {
        Anchor {
            seqno,
            root: hash(1),
            file: hash(2),
            state: hash(3),
        }
    }

    fn manifest(fill: u8, length: usize) -> Result<(Vec<u8>, ObjectRef), Error> {
        let raw = vec![fill; length];
        let carrier = object_value(5, &raw)?;
        match carrier.reference.as_slice() {
            [reference] => Ok((raw, reference.clone())),
            _ => Err(Error("script")),
        }
    }

    fn large_manifest(fill: u8, length: u32) -> Result<(ObjectRef, Vec<u8>), Error> {
        let length_usize = length as usize;
        let count = length_usize.div_ceil(CHUNK_BYTES);
        if count == 0 || count > 64 {
            return Err(Error("script"));
        }
        let object_id = hash(
            100_000u32
                .checked_add(u32::from(fill))
                .ok_or(Error("script"))?,
        );
        let chunk_length = length_usize.min(CHUNK_BYTES);
        let chunk = vec![fill; chunk_length];
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&object_id);
        preimage.push(0);
        preimage.extend_from_slice(&chunk);
        let first = digest("object-chunk", &preimage)?;
        let mut chunk_hashes = vec![hash(999); count];
        chunk_hashes[0] = first;
        Ok((
            ObjectRef {
                kind: 5,
                byte_length: length,
                object_id,
                chunk_hashes,
            },
            chunk,
        ))
    }

    fn emit<T>(
        out: &mut String,
        operation: &str,
        result: Result<T, Error>,
        reserved: usize,
        detail: impl FnOnce(T) -> String,
    ) {
        match result {
            Ok(value) => out.push_str(&format!(
                "OK {operation} {} {reserved}\n",
                detail(value)
            )),
            Err(error) => out.push_str(&format!(
                "ERR {operation} {} {reserved}\n",
                error.0
            )),
        }
    }

    let script = fs::read_to_string(input).map_err(|_| Error("read"))?;
    let mut store: Option<ScopedObjectStore> = None;
    let mut out = String::new();

    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let operation = fields.next().ok_or(Error("script"))?;
        match operation {
            "config" => {
                let global = number::<usize>(&mut fields)?;
                let ttl = number::<u64>(&mut fields)?;
                if fields.next().is_some() {
                    return Err(Error("script"));
                }
                store = Some(ScopedObjectStore::new(global, ttl));
                out.push_str("OK config - 0\n");
            }
            "publish" | "publish_bad" => {
                let principal = hash(number::<u32>(&mut fields)?);
                let seqno = number::<u32>(&mut fields)?;
                let fill = number::<u8>(&mut fields)?;
                let length = number::<usize>(&mut fields)?;
                let now = number::<u64>(&mut fields)?;
                if fields.next().is_some() {
                    return Err(Error("script"));
                }
                let (mut raw, reference) = manifest(fill, length)?;
                if operation == "publish_bad" {
                    let first = raw.first_mut().ok_or(Error("script"))?;
                    *first ^= 1;
                }
                let active = store.as_mut().ok_or(Error("script"))?;
                let result = active.publish(&principal, &anchor(seqno), &reference, &raw, now);
                let reserved = active.reserved();
                emit(&mut out, operation, result, reserved, |_| "-".to_string());
            }
            "put_large" => {
                let principal = hash(number::<u32>(&mut fields)?);
                let seqno = number::<u32>(&mut fields)?;
                let length = number::<u32>(&mut fields)?;
                let fill = number::<u8>(&mut fields)?;
                let now = number::<u64>(&mut fields)?;
                if fields.next().is_some() {
                    return Err(Error("script"));
                }
                let (reference, chunk) = large_manifest(fill, length)?;
                let active = store.as_mut().ok_or(Error("script"))?;
                let result = active.put(&principal, &anchor(seqno), &reference, 0, &chunk, now);
                let reserved = active.reserved();
                emit(&mut out, operation, result, reserved, |_| "-".to_string());
            }
            "get" => {
                let principal = hash(number::<u32>(&mut fields)?);
                let seqno = number::<u32>(&mut fields)?;
                let fill = number::<u8>(&mut fields)?;
                let length = number::<usize>(&mut fields)?;
                let index = number::<u8>(&mut fields)?;
                let now = number::<u64>(&mut fields)?;
                if fields.next().is_some() {
                    return Err(Error("script"));
                }
                let (_, reference) = manifest(fill, length)?;
                let active = store.as_mut().ok_or(Error("script"))?;
                let result = active.get(&principal, &anchor(seqno), &reference, index, now);
                let reserved = active.reserved();
                emit(&mut out, operation, result, reserved, |value| value.len().to_string());
            }
            "reserved" => {
                if fields.next().is_some() {
                    return Err(Error("script"));
                }
                let active = store.as_ref().ok_or(Error("script"))?;
                out.push_str(&format!("STATE reserved {}\n", active.reserved()));
            }
            _ => return Err(Error("script")),
        }
    }

    fs::write(output, out).map_err(|_| Error("write"))
}
