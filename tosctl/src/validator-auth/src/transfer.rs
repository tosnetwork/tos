use crate::{
    codec::{encode, Error, Hash},
    crypto::{digest, object_id},
    types::{Anchor, ObjectRef, ObjectValue},
};
use std::collections::BTreeMap;
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

#[derive(Clone, Copy, Default)]
struct ScopedUsage {
    bytes: usize,
    objects: usize,
}

#[derive(Clone)]
struct ScopedEntry {
    principal: Hash,
    manifest: ObjectRef,
    chunks: BTreeMap<u8, Vec<u8>>,
    expires: u64,
}

const PRINCIPAL_OBJECT_LIMIT: usize = 4;
const PRINCIPAL_BYTE_LIMIT: usize = 67_108_864;
const GLOBAL_BYTE_LIMIT: usize = 268_435_456;
const PRINCIPAL_TABLE_LIMIT: usize = 1024;

pub struct ScopedObjectStore {
    entries: BTreeMap<(Hash, Hash), ScopedEntry>,
    principals: BTreeMap<Hash, ScopedUsage>,
    used: usize,
    limit: usize,
    ttl: u64,
    clock: u64,
}

impl ScopedObjectStore {
    pub fn new(global_bytes: usize, ttl: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            principals: BTreeMap::new(),
            used: 0,
            limit: global_bytes.min(GLOBAL_BYTE_LIMIT),
            ttl: ttl.clamp(1, 3600),
            clock: 0,
        }
    }

    fn scope(principal: &Hash, anchor: &Anchor) -> Result<Hash, Error> {
        if *principal == [0; 32]
            || anchor.seqno == u32::MAX
            || anchor.root == [0; 32]
            || anchor.file == [0; 32]
            || anchor.state == [0; 32]
        {
            return Err(Error("object-scope"));
        }
        let mut input = Vec::new();
        input.extend_from_slice(principal);
        input.extend_from_slice(&encode(anchor)?);
        digest("local-object-scope", &input)
    }

    fn expire(&mut self, now: u64) -> Result<(), Error> {
        if now < self.clock {
            return Err(Error("storage-clock-regression"));
        }
        self.clock = now;

        let mut expired = Vec::new();
        for (key, entry) in &self.entries {
            if entry.expires <= now {
                expired.push(*key);
            }
        }

        for key in expired {
            let entry = self.entries.get(&key).ok_or(Error("storage-accounting"))?;
            let length = entry.manifest.byte_length as usize;
            let principal = entry.principal;
            let usage = *self.principals.get(&principal).ok_or(Error("storage-accounting"))?;
            if usage.objects == 0 || usage.bytes < length || self.used < length {
                return Err(Error("storage-accounting"));
            }

            let next_used = self.used.checked_sub(length).ok_or(Error("storage-accounting"))?;
            let next_bytes = usage.bytes.checked_sub(length).ok_or(Error("storage-accounting"))?;
            let next_objects = usage.objects.checked_sub(1).ok_or(Error("storage-accounting"))?;

            if self.entries.remove(&key).is_none() {
                return Err(Error("storage-accounting"));
            }
            self.used = next_used;
            if next_objects == 0 {
                if self.principals.remove(&principal).is_none() {
                    return Err(Error("storage-accounting"));
                }
            } else {
                self.principals
                    .insert(principal, ScopedUsage { bytes: next_bytes, objects: next_objects });
            }
        }
        Ok(())
    }

    fn admit(&self, principal: &Hash, reference: &ObjectRef, now: u64) -> Result<(), Error> {
        let current = self.principals.get(principal);
        let usage = match current {
            Some(value) => *value,
            None => ScopedUsage::default(),
        };
        let length = reference.byte_length as usize;

        let principal_table_exhausted =
            current.is_none() && self.principals.len() >= PRINCIPAL_TABLE_LIMIT;
        if principal_table_exhausted {
            return Err(Error("storage-unavailable"));
        }

        if usage.objects >= PRINCIPAL_OBJECT_LIMIT {
            return Err(Error("principal-storage-quota"));
        }

        let principal_remaining = PRINCIPAL_BYTE_LIMIT
            .checked_sub(usage.bytes)
            .ok_or(Error("principal-storage-quota"))?;
        let principal_bytes_exhausted =
            usage.bytes > PRINCIPAL_BYTE_LIMIT || length > principal_remaining;
        if principal_bytes_exhausted {
            return Err(Error("principal-storage-quota"));
        }

        let global_remaining =
            self.limit.checked_sub(self.used).ok_or(Error("global-storage-quota"))?;
        let global_bytes_exhausted = self.used > self.limit || length > global_remaining;
        if global_bytes_exhausted {
            return Err(Error("global-storage-quota"));
        }

        now.checked_add(self.ttl).ok_or(Error("storage-clock-overflow"))?;
        Ok(())
    }

    pub fn put(
        &mut self,
        principal: &Hash,
        anchor: &Anchor,
        reference: &ObjectRef,
        index: u8,
        bytes: &[u8],
        now: u64,
    ) -> Result<Hash, Error> {
        let scoped = Self::scope(principal, anchor)?;
        validate_manifest(reference)?;
        self.expire(now)?;
        let id = object_id("object_ref", reference)?;
        let key = (scoped, id);

        if let Some(found) = self.entries.get_mut(&key) {
            validate_chunk(reference, index, bytes)?;
            match found.chunks.get(&index) {
                Some(existing) if existing.as_slice() != bytes => {
                    return Err(Error("chunk-conflict"));
                }
                Some(_) => {}
                None => {
                    found.chunks.insert(index, bytes.to_vec());
                }
            }
            return Ok(id);
        }

        self.admit(principal, reference, now)?;
        validate_chunk(reference, index, bytes)?;

        let length = reference.byte_length as usize;
        let expires = now.checked_add(self.ttl).ok_or(Error("storage-clock-overflow"))?;
        let next_used = self.used.checked_add(length).ok_or(Error("global-storage-quota"))?;
        let usage = match self.principals.get(principal) {
            Some(value) => *value,
            None => ScopedUsage::default(),
        };
        let next_bytes = usage.bytes.checked_add(length).ok_or(Error("principal-storage-quota"))?;
        let next_objects = usage.objects.checked_add(1).ok_or(Error("principal-storage-quota"))?;
        let mut chunks = BTreeMap::new();
        chunks.insert(index, bytes.to_vec());
        let entry =
            ScopedEntry { principal: *principal, manifest: reference.clone(), chunks, expires };

        if self.entries.insert(key, entry).is_some() {
            return Err(Error("storage-accounting"));
        }
        self.used = next_used;
        self.principals
            .insert(*principal, ScopedUsage { bytes: next_bytes, objects: next_objects });
        Ok(id)
    }

    pub fn get(
        &mut self,
        principal: &Hash,
        anchor: &Anchor,
        reference: &ObjectRef,
        index: u8,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let scoped = Self::scope(principal, anchor)?;
        validate_manifest(reference)?;
        if usize::from(index) >= reference.chunk_hashes.len() {
            return Err(Error("chunk-index"));
        }
        self.expire(now)?;
        let id = object_id("object_ref", reference)?;
        let found = self.entries.get(&(scoped, id)).ok_or(Error("object-unavailable"))?;
        found.chunks.get(&index).cloned().ok_or(Error("object-unavailable"))
    }

    pub fn publish(
        &mut self,
        principal: &Hash,
        anchor: &Anchor,
        reference: &ObjectRef,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        let scoped = Self::scope(principal, anchor)?;
        validate_manifest(reference)?;
        if bytes.len() != reference.byte_length as usize {
            return Err(Error("object-length"));
        }
        self.expire(now)?;
        let id = object_id("object_ref", reference)?;
        let key = (scoped, id);

        let existing_expiry = match self.entries.get(&key) {
            Some(found) => Some(found.expires),
            None => {
                self.admit(principal, reference, now)?;
                None
            }
        };

        let canonical = object_value(reference.kind, bytes)?;
        match canonical.reference.as_slice() {
            [only] if only == reference => {}
            _ => return Err(Error("published-object-binding")),
        }

        let expires = match existing_expiry {
            Some(value) => value,
            None => now.checked_add(self.ttl).ok_or(Error("storage-clock-overflow"))?,
        };
        let mut chunks = BTreeMap::new();
        for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
            let index = u8::try_from(index).map_err(|_| Error("manifest-count"))?;
            chunks.insert(index, chunk.to_vec());
        }
        let entry =
            ScopedEntry { principal: *principal, manifest: reference.clone(), chunks, expires };

        if existing_expiry.is_some() {
            let found = self.entries.get_mut(&key).ok_or(Error("storage-accounting"))?;
            *found = entry;
            return Ok(());
        }

        let length = reference.byte_length as usize;
        let next_used = self.used.checked_add(length).ok_or(Error("global-storage-quota"))?;
        let usage = match self.principals.get(principal) {
            Some(value) => *value,
            None => ScopedUsage::default(),
        };
        let next_bytes = usage.bytes.checked_add(length).ok_or(Error("principal-storage-quota"))?;
        let next_objects = usage.objects.checked_add(1).ok_or(Error("principal-storage-quota"))?;

        if self.entries.insert(key, entry).is_some() {
            return Err(Error("storage-accounting"));
        }
        self.used = next_used;
        self.principals
            .insert(*principal, ScopedUsage { bytes: next_bytes, objects: next_objects });
        Ok(())
    }

    pub fn reserved(&self) -> usize {
        self.used
    }
}
