/*
 * Rust port of `encode_jvm_storage_value` (jvm/core/storage-cell-host.cpp).
 *
 * Layout: a linked chain of cells, each carrying up to 127 raw bytes
 * and a 1-bit "has_next" tag. Final chunk has has_next=0; intermediate
 * chunks have has_next=1 with a ref to the next chunk.  Empty value
 * encodes as a single cell containing only `0` (1 bit).
 *
 * The 16-cell wrapper margin (max_depth − 16 = 1008) is enforced so
 * downstream wrappers (StateInit, JVAC) can layer refs on top without
 * tripping `vm::CellTraits::max_depth` on the validator side.
 */
use anyhow::{Context, Result, anyhow};
use chain_block::{BuilderData, Cell, IBitstring};

pub const JVM_STORAGE_VALUE_CHUNK_BYTES: usize = 127;
pub const JVM_STORAGE_VALUE_MAX_BYTES: usize = 1024 * 1024;
const JVM_STORAGE_VALUE_MAX_CHUNKS: usize = 1024 - 16;

/// Encode a byte string as a JVM storage-value chunk chain.
///
/// Empty input encodes as the canonical empty cell (single `0` bit).
/// Returns an error when the input exceeds the consensus 1 MiB cap or
/// when chunk depth would exceed the wrapper budget.
pub fn encode_jvm_storage_value(value: &[u8]) -> Result<Cell> {
    if value.len() > JVM_STORAGE_VALUE_MAX_BYTES {
        return Err(anyhow!(
            "jvm storage value exceeds {} bytes",
            JVM_STORAGE_VALUE_MAX_BYTES
        ));
    }
    if value.is_empty() {
        return encode_empty_value();
    }
    let chunks = value.len().div_ceil(JVM_STORAGE_VALUE_CHUNK_BYTES);
    if chunks > JVM_STORAGE_VALUE_MAX_CHUNKS {
        return Err(anyhow!(
            "jvm storage value chunk count {chunks} exceeds wrapper-margin cap"
        ));
    }

    let mut next: Option<Cell> = None;
    // Build the chain back-to-front so the head cell references the
    // tail through nested refs.
    for i in (0..chunks).rev() {
        let start = i * JVM_STORAGE_VALUE_CHUNK_BYTES;
        let end = (start + JVM_STORAGE_VALUE_CHUNK_BYTES).min(value.len());
        let mut cb = BuilderData::new();
        cb.append_raw(&value[start..end], (end - start) * 8)
            .context("jvm storage value chunk append failed")?;
        match next {
            Some(child) => {
                cb.append_bit_one()
                    .context("jvm storage value has_next bit failed")?;
                cb.checked_append_reference(child)
                    .context("jvm storage value chunk ref append failed")?;
            }
            None => {
                cb.append_bit_zero()
                    .context("jvm storage value tail bit failed")?;
            }
        }
        next = Some(
            cb.into_cell()
                .context("jvm storage value chunk finalize failed")?,
        );
    }
    Ok(next.expect("non-empty input always produces at least one chunk"))
}

fn encode_empty_value() -> Result<Cell> {
    let mut cb = BuilderData::new();
    cb.append_bit_zero()
        .context("jvm storage empty-value bit failed")?;
    cb.into_cell()
        .context("jvm storage empty-value finalize failed")
}
