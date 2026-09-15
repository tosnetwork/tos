use crate::{cells, native, native_history::NativeFinalizedHistory};
use chain_block::{BuilderData, Cell, CellType, HashmapE, HashmapType, SliceData};
use std::{collections::BTreeMap, sync::Arc};
use tos_validator_auth::{
    codec::{decode, Error, Hash},
    transfer::{validate_object, ObjectReader, CHUNK_BYTES, INLINE_BYTES},
    types::{Anchor, Authorizations, ObjectRef},
};
pub const NATIVE_EVIDENCE_TAG: u32 = 0x76616531;
pub const NATIVE_AUTHORIZATIONS_LIMIT: usize = 4 * INLINE_BYTES + 4096;
type ChunkKey = [u8; 33];
fn need(ok: bool, code: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error(code))
    }
}
fn key(id: &Hash, index: u8) -> ChunkKey {
    let mut result = [0; 33];
    result[..32].copy_from_slice(id);
    result[32] = index;
    result
}
fn bits(k: &ChunkKey) -> Result<SliceData, Error> {
    native(SliceData::load_bitstring(native(BuilderData::with_raw(k.to_vec(), 264))?))
}
fn declared(cell: Cell, limit: usize) -> Result<usize, Error> {
    need(
        cell.cell_type() == CellType::Ordinary
            && cell.level() == 0
            && cell.bit_length() == 336
            && cell.references_count() == 1,
        "auth-bytes-shape",
    )?;
    let mut s = native(SliceData::load_cell(cell))?;
    need(
        native(s.get_next_u32())? == 0x76616231 && native(s.get_next_u16())? == 1,
        "auth-bytes-version",
    )?;
    let n = native(s.get_next_u32())? as usize;
    need(n != 0 && n <= limit, "evidence-byte-bound")?;
    Ok(n)
}
/// A transaction-contained set of typed objects. Construction does not confer
/// owner, possession, identity or governance authority.
pub struct NativeEvidence {
    authorizations: Authorizations,
    header: Cell,
    chunks: Arc<BTreeMap<ChunkKey, Vec<u8>>>,
}
impl NativeEvidence {
    /// Charge deterministic byte bounds before decoding/hashing them. Native
    /// execution chooses gas prices; no IO or cache affects these charges.
    pub fn open(
        root: Cell,
        mut charge: impl FnMut(usize) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        need(
            root.cell_type() == CellType::Ordinary
                && root.level() == 0
                && root.bit_length() == 49
                && root.references_count() >= 2,
            "evidence-shape",
        )?;
        let mut s = native(SliceData::load_cell(root))?;
        need(
            native(s.get_next_u32())? == NATIVE_EVIDENCE_TAG && native(s.get_next_u16())? == 1,
            "evidence-version",
        )?;
        let present = native(s.get_next_bit())?;
        need(s.remaining_references() == 2 + usize::from(present), "evidence-shape")?;
        let auth = native(s.checked_drain_reference())?;
        let header = native(s.checked_drain_reference())?;
        charge(declared(auth.clone(), NATIVE_AUTHORIZATIONS_LIMIT)?)?;
        let a: Authorizations = decode(&cells::unpack_bytes(auth, NATIVE_AUTHORIZATIONS_LIMIT)?)?;
        if a.owner.is_empty() {
            need(
                header.cell_type() == CellType::Ordinary
                    && header.bit_length() == 0
                    && header.references_count() == 0,
                "evidence-unused-header",
            )?;
        }
        let objects: Vec<_> = a
            .owner
            .iter()
            .map(|v| (&v.proof.proof, 5))
            .chain(a.administration.iter().map(|v| (&v.certificate, 4)))
            .chain(a.governance.iter().map(|v| (&v.certificate, 4)))
            .collect();
        let mut expected = BTreeMap::new();
        let mut manifests = BTreeMap::new();
        let mut remaining: usize = 67_108_864;
        for &(v, kind) in &objects {
            validate_object(v, kind)?;
            let size = if v.inline.is_empty() {
                v.reference[0].byte_length as usize
            } else {
                v.inline.len()
            };
            remaining = remaining.checked_sub(size).ok_or(Error("attachment-budget"))?;
            let Some(r) = v.reference.first() else { continue };
            if let Some(old) = manifests.insert(r.object_id, r) {
                need(old == r, "evidence-manifest-conflict")?;
            }
            for i in 0..r.chunk_hashes.len() {
                let length = (r.byte_length as usize)
                    .checked_sub(i.checked_mul(CHUNK_BYTES).ok_or(Error("chunk-length"))?)
                    .ok_or(Error("chunk-length"))?
                    .min(CHUNK_BYTES);
                expected.insert(
                    key(&r.object_id, u8::try_from(i).map_err(|_| Error("chunk-index"))?),
                    length,
                );
            }
        }
        // Only admitted manifest keys may be enumerated; unused entries fail
        // before their payload is decoded or recursively traversed.
        let supplied = HashmapE::with_hashmap(
            264,
            if present { Some(native(s.checked_drain_reference())?) } else { None },
        );
        let mut canonical = HashmapE::with_bit_len(264);
        let mut chunks_cells = BTreeMap::new();
        let mut failure = None;
        let complete = native(supplied.iterate_slices(|k, v| {
            let checked = (|| -> Result<(), Error> {
                need(
                    k.remaining_bits() == 264
                        && v.remaining_bits() == 0
                        && v.remaining_references() == 1,
                    "evidence-chunk-shape",
                )?;
                let k: ChunkKey =
                    k.get_bytestring(0).try_into().map_err(|_| Error("evidence-chunk-shape"))?;
                let n = expected.get(&k).ok_or(Error("evidence-extra-chunk"))?;
                let cell = native(v.reference(0))?;
                need(declared(cell.clone(), CHUNK_BYTES)? == *n, "evidence-chunk-length")?;
                chunks_cells.insert(k, cell.clone());
                need(native(canonical.setref(bits(&k)?, cell))?.is_none(), "evidence-dictionary")?;
                Ok(())
            })();
            match checked {
                Ok(()) => Ok(true),
                Err(e) => {
                    failure = Some(e);
                    Ok(false)
                }
            }
        }))?;
        if let Some(e) = failure {
            return Err(e);
        }
        need(complete, "evidence-dictionary")?;
        need(chunks_cells.len() == expected.len(), "evidence-missing-chunk")?;
        need(
            supplied.data().map(Cell::repr_hash) == canonical.data().map(Cell::repr_hash),
            "evidence-dictionary",
        )?;
        charge(67_108_864_usize.checked_sub(remaining).ok_or(Error("attachment-budget"))?)?;
        let mut chunks = BTreeMap::new();
        for (k, cell) in chunks_cells {
            chunks.insert(
                k,
                cells::unpack_bytes(cell, *expected.get(&k).ok_or(Error("evidence-extra-chunk"))?)?,
            );
        }
        let result = Self { authorizations: a.clone(), header, chunks: Arc::new(chunks) };
        let mut reader = result.reader();
        for (v, kind) in objects {
            reader.resolve(v, kind)?;
        }
        Ok(result)
    }
    pub fn authorizations(&self) -> &Authorizations {
        &self.authorizations
    }
    pub fn reader(&self) -> ObjectReader<impl FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>> {
        let chunks = self.chunks.clone();
        ObjectReader::new(move |r: &ObjectRef, i: u8| {
            chunks.get(&key(&r.object_id, i)).cloned().ok_or(Error("evidence-missing-chunk"))
        })
    }
    pub fn authenticate_owner<F>(
        &self,
        history: &NativeFinalizedHistory<F>,
    ) -> Result<Anchor, Error>
    where
        F: Fn(&chain_block::BlockIdExt, usize) -> Result<Vec<u8>, Error>,
    {
        need(self.authorizations.owner.len() == 1, "evidence-owner-absent")?;
        let expected = &self.authorizations.owner[0].proof.anchor;
        let actual = history.authenticate_header(expected.seqno, self.header.clone())?;
        need(&actual == expected, "evidence-owner-anchor")?;
        Ok(actual)
    }
}
