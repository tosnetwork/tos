use crate::native;
use chain_block::{BocReader, BuilderData, Cell, CellType, IBitstring, SliceData};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, io::Cursor};
use tos_validator_auth::codec::Error;
pub const MAX_OBJECT: usize = 33_554_432;
pub const MAX_BOC: usize = 67_108_864;
const MAX_CELLS: usize = 400_001;
fn capacity(size: usize) -> usize {
    let mut result = 120;
    while size > 4 * result {
        result *= 4;
    }
    result
}
fn pack_node(raw: &[u8]) -> Result<Cell, Error> {
    let mut builder = BuilderData::new();
    if raw.len() <= 120 {
        native(builder.append_bit_zero())?;
        native(builder.append_bits(raw.len(), 7))?;
        native(builder.append_raw(raw, raw.len() * 8))?;
    } else {
        let cap = capacity(raw.len());
        native(builder.append_bit_one())?;
        native(builder.append_bits(raw.len().div_ceil(cap), 3))?;
        native(builder.append_u32(raw.len() as u32))?;
        for chunk in raw.chunks(cap) {
            native(builder.checked_append_reference(pack_node(chunk)?))?;
        }
    }
    native(builder.into_cell())
}
pub fn pack_bytes(raw: &[u8]) -> Result<Cell, Error> {
    if raw.is_empty() || raw.len() > MAX_OBJECT {
        return Err(Error("object-bound"));
    }
    let mut builder = BuilderData::new();
    native(builder.append_u32(0x76616231))?;
    native(builder.append_u16(1))?;
    native(builder.append_u32(raw.len() as u32))?;
    native(builder.append_raw(&Sha256::digest(raw), 256))?;
    native(builder.checked_append_reference(pack_node(raw)?))?;
    native(builder.into_cell())
}
fn unpack_node(
    cell: Cell,
    expected: usize,
    depth: u8,
    occurrences: &mut usize,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    *occurrences = occurrences.checked_add(1).ok_or(Error("tree-canonical"))?;
    if depth > 10
        || *occurrences > 400_000
        || cell.level() != 0
        || cell.cell_type() != CellType::Ordinary
    {
        return Err(Error("tree-canonical"));
    }
    let mut slice = native(SliceData::load_cell(cell))?;
    let branch = native(slice.get_next_bit())?;
    if expected <= 120 {
        let n = native(slice.get_next_int(7))? as usize;
        if branch
            || n != expected
            || n == 0
            || slice.remaining_bits() != n * 8
            || slice.remaining_references() != 0
        {
            return Err(Error("tree-canonical"));
        }
        out.extend_from_slice(&native(slice.get_next_bits(n * 8))?);
    } else {
        if !branch || slice.remaining_bits() != 35 {
            return Err(Error("tree-canonical"));
        }
        let n = native(slice.get_next_int(3))? as usize;
        let length = native(slice.get_next_u32())? as usize;
        let cap = capacity(expected);
        if length != expected
            || n != expected.div_ceil(cap)
            || !(2..=4).contains(&n)
            || slice.remaining_references() != n
        {
            return Err(Error("tree-canonical"));
        }
        for offset in (0..expected).step_by(cap) {
            unpack_node(
                native(slice.checked_drain_reference())?,
                cap.min(expected - offset),
                depth + 1,
                occurrences,
                out,
            )?;
        }
    }
    Ok(())
}
pub fn unpack_bytes(cell: Cell, remaining: usize) -> Result<Vec<u8>, Error> {
    if cell.level() != 0 || cell.cell_type() != CellType::Ordinary {
        return Err(Error("cell-level"));
    }
    let mut slice = native(SliceData::load_cell(cell))?;
    if slice.remaining_bits() != 336 || slice.remaining_references() != 1 {
        return Err(Error("auth-bytes-shape"));
    }
    if native(slice.get_next_u32())? != 0x76616231 || native(slice.get_next_u16())? != 1 {
        return Err(Error("auth-bytes-version"));
    }
    let length = native(slice.get_next_u32())? as usize;
    if length == 0 || length > MAX_OBJECT {
        return Err(Error("object-bound"));
    }
    if length > remaining {
        return Err(Error("state-resource"));
    }
    let expected = native(slice.get_next_bits(256))?;
    let mut raw = Vec::with_capacity(length);
    unpack_node(native(slice.checked_drain_reference())?, length, 0, &mut 0, &mut raw)?;
    if Sha256::digest(&raw).as_slice() != expected {
        return Err(Error("auth-bytes-hash"));
    }
    Ok(raw)
}
/// Inspect declared sizes before the native reader allocates its cell/index tables.
pub fn read_boc(bytes: &[u8], all_reachable: bool) -> Result<Cell, Error> {
    if bytes.is_empty() || bytes.len() > MAX_BOC {
        return Err(Error("boc-bound"));
    }
    let mut cursor = Cursor::new(bytes);
    let mut reader = BocReader::new().set_max_cell_depth(1024);
    let (header, _) = native(reader.read_header(&mut cursor))?;
    if header.roots_count != 1 || header.cells_count == 0 || header.cells_count > MAX_CELLS {
        return Err(Error("boc-header-bound"));
    }
    let index = if header.index_included {
        header.cells_count.checked_mul(header.offset_size).ok_or(Error("boc-header-bound"))?
    } else {
        0
    };
    let size = (cursor.position() as usize)
        .checked_add(index)
        .and_then(|n| n.checked_add(header.tot_cells_size))
        .and_then(|n| n.checked_add(if header.has_crc { 4 } else { 0 }))
        .ok_or(Error("boc-header-bound"))?;
    if size != bytes.len() {
        return Err(Error("boc-header-bound"));
    }
    cursor.set_position(0);
    let parsed = native(reader.read(&mut cursor))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error("boc-trailing"));
    }
    let root = native(parsed.withdraw_single_root())?;
    if all_reachable {
        let mut seen = HashSet::new();
        let mut pending = vec![root.clone()];
        while let Some(cell) = pending.pop() {
            if !seen.insert(cell.repr_hash()) {
                continue;
            }
            if seen.len() > header.cells_count {
                return Err(Error("boc-unreachable-cells"));
            }
            for n in 0..cell.references_count() {
                pending.push(native(cell.reference(n))?);
            }
        }
        if seen.len() != header.cells_count {
            return Err(Error("boc-unreachable-cells"));
        }
    }
    Ok(root)
}
pub fn serialize_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes = native(chain_block::write_boc(&pack_bytes(raw)?))?;
    if bytes.len() > MAX_BOC {
        return Err(Error("boc-bound"));
    }
    Ok(bytes)
}
pub fn deserialize_bytes(bytes: &[u8], remaining: usize) -> Result<Vec<u8>, Error> {
    unpack_bytes(read_boc(bytes, false)?, remaining)
}
