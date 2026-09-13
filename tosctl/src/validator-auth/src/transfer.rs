use crate::{
    codec::{Error, Hash},
    crypto::digest,
    types::{ObjectRef, ObjectValue},
};
pub const CHUNK_BYTES: usize = 1_048_576;
pub const INLINE_BYTES: usize = 65_536;
fn limit(kind: u8) -> Result<usize, Error> {
    match kind {
        5 => Ok(67_108_864),
        1..=7 => Ok(33_554_432),
        _ => Err(Error("object-kind")),
    }
}
pub fn transferred_id(kind: u8, bytes: &[u8]) -> Result<Hash, Error> {
    let maximum = limit(kind)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error("object-length"));
    }
    let domain = ["", "key", "policy", "committee", "certificate", "proof", "envelope", "update"]
        [usize::from(kind)];
    digest(domain, bytes)
}
fn chunk_hash(id: &Hash, index: u8, bytes: &[u8]) -> Result<Hash, Error> {
    let mut input = Vec::with_capacity(33 + bytes.len());
    input.extend_from_slice(id);
    input.push(index);
    input.extend_from_slice(bytes);
    digest("object-chunk", &input)
}
pub fn object_value(kind: u8, bytes: &[u8]) -> Result<ObjectValue, Error> {
    let id = transferred_id(kind, bytes)?;
    if bytes.len() <= INLINE_BYTES {
        return Ok(ObjectValue { kind, inline: bytes.to_vec(), reference: vec![] });
    }
    let mut hashes = Vec::new();
    for (i, part) in bytes.chunks(CHUNK_BYTES).enumerate() {
        hashes.push(chunk_hash(&id, u8::try_from(i).map_err(|_| Error("manifest-count"))?, part)?);
    }
    Ok(ObjectValue {
        kind,
        inline: vec![],
        reference: vec![ObjectRef {
            kind,
            byte_length: u32::try_from(bytes.len()).map_err(|_| Error("object-length"))?,
            object_id: id,
            chunk_hashes: hashes,
        }],
    })
}
pub fn validate_manifest(manifest: &ObjectRef) -> Result<(), Error> {
    let maximum = limit(manifest.kind)?;
    let size = manifest.byte_length as usize;
    if size <= INLINE_BYTES || size > maximum {
        return Err(Error("manifest-length"));
    }
    if manifest.chunk_hashes.len() != size.div_ceil(CHUNK_BYTES) {
        return Err(Error("manifest-count"));
    }
    Ok(())
}
pub fn validate_object(value: &ObjectValue, kind: u8) -> Result<(), Error> {
    limit(kind)?;
    if value.kind != kind {
        return Err(Error("object-kind"));
    }
    if value.inline.is_empty() {
        if value.reference.len() != 1 {
            return Err(Error("object-representation"));
        }
        let reference = &value.reference[0];
        if reference.kind != kind {
            return Err(Error("object-kind"));
        }
        validate_manifest(reference)
    } else if value.inline.len() > INLINE_BYTES || !value.reference.is_empty() {
        Err(Error("object-representation"))
    } else {
        Ok(())
    }
}
pub fn validate_chunk(manifest: &ObjectRef, index: u8, bytes: &[u8]) -> Result<(), Error> {
    validate_manifest(manifest)?;
    let i = usize::from(index);
    if i >= manifest.chunk_hashes.len() {
        return Err(Error("chunk-index"));
    }
    let remaining = (manifest.byte_length as usize)
        .checked_sub(i.checked_mul(CHUNK_BYTES).ok_or(Error("chunk-index"))?)
        .ok_or(Error("chunk-index"))?;
    if bytes.len() != remaining.min(CHUNK_BYTES) {
        return Err(Error("chunk-length"));
    }
    if chunk_hash(&manifest.object_id, index, bytes)? != manifest.chunk_hashes[i] {
        return Err(Error("chunk-hash"));
    }
    Ok(())
}
// A single reader is shared by all attachments of an operation. The callback
// resolves admitted manifests; it is not a URL or arbitrary file fetch API.
pub struct ObjectReader<F> {
    fetch: F,
    remaining: usize,
}
impl<F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>> ObjectReader<F> {
    pub fn new(fetch: F) -> Self {
        Self { fetch, remaining: 67_108_864 }
    }
    pub fn resolve(&mut self, value: &ObjectValue, kind: u8) -> Result<Vec<u8>, Error> {
        validate_object(value, kind)?;
        let size = if value.inline.is_empty() {
            value.reference[0].byte_length as usize
        } else {
            value.inline.len()
        };
        self.remaining = self.remaining.checked_sub(size).ok_or(Error("attachment-budget"))?;
        if !value.inline.is_empty() {
            return Ok(value.inline.clone());
        }
        let reference = &value.reference[0];
        let mut out = Vec::with_capacity(size);
        for i in 0..reference.chunk_hashes.len() {
            let index = u8::try_from(i).map_err(|_| Error("chunk-index"))?;
            let chunk = (self.fetch)(reference, index)?;
            validate_chunk(reference, index, &chunk)?;
            out.extend_from_slice(&chunk);
        }
        if transferred_id(kind, &out)? != reference.object_id {
            return Err(Error("object-hash"));
        }
        Ok(out)
    }
}
