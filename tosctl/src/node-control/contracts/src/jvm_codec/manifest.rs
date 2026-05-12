/*
 * Rust port of `encode_jvm_method_manifest` (jvm/core/class-manifest.cpp).
 *
 * Wire layout:
 *
 *   jvm_manifest#4a564d32 ("JVM2")
 *     schema_version:uint8 (=1)
 *     count:uint16
 *     entries:^(JvmManifestNode chain)?  -- absent when count == 0
 *
 *   jvm_manifest_node
 *     method_id:uint32
 *     has_next:bit
 *     next:^JvmManifestNode?              -- only when has_next == 1
 *     class_name:^Cell                    -- chunk-encoded UTF-8
 *     method_name:^Cell                   -- chunk-encoded UTF-8
 *     method_spec:^Cell                   -- chunk-encoded UTF-8 JVM type spec
 *
 * The C++ encoder builds the chain head-to-tail (last entry first so
 * each node's `next` is the cell built in the previous iteration);
 * we mirror that exactly so cell hashes match byte-for-byte.
 *
 * Deploy-time the manifest_root cell's hash is bound into the wc=3
 * address derivation (`address.rs::derive_jvm_contract_address`), so
 * any drift between Rust and C++ encoders here would surface as the
 * derived address not matching the validator's expected address.
 */
use anyhow::{Context, Result, anyhow};
use chain_block::{BuilderData, Cell, IBitstring};

use super::storage_value::encode_jvm_storage_value;

pub const JVM_METHOD_MANIFEST_MAGIC: u32 = 0x4a56_4d32; // "JVM2"
pub const JVM_METHOD_MANIFEST_SCHEMA_VERSION: u8 = 1;
pub const JVM_METHOD_MANIFEST_MAX_ENTRIES: usize = 1024;

#[derive(Clone, Debug)]
pub struct JvmMethodManifestEntry {
    pub method_id: u32,
    pub class_name: String,
    pub method_name: String,
    pub method_spec: String,
}

impl JvmMethodManifestEntry {
    pub fn new(
        method_id: u32,
        class_name: impl Into<String>,
        method_name: impl Into<String>,
        method_spec: impl Into<String>,
    ) -> Self {
        Self {
            method_id,
            class_name: class_name.into(),
            method_name: method_name.into(),
            method_spec: method_spec.into(),
        }
    }
}

/// Encode the per-account method manifest as a single root cell.
///
/// Empty `entries` produce a header-only root (no child ref). With
/// entries, the root carries one child ref that points to the first
/// node in a back-linked chain.
///
/// Returns `Err` when:
///   * `entries.len()` exceeds the consensus cap (1024)
///   * any entry has a duplicate `method_id`
///   * any entry has an empty / NUL-bearing string field
pub fn encode_jvm_method_manifest(
    entries: &[JvmMethodManifestEntry],
) -> Result<Cell> {
    validate_entries(entries)?;

    let chain_head = if entries.is_empty() {
        None
    } else {
        Some(encode_chain(entries)?)
    };

    let mut root = BuilderData::new();
    root.append_u32(JVM_METHOD_MANIFEST_MAGIC)
        .context("jvm manifest magic append failed")?;
    root.append_u8(JVM_METHOD_MANIFEST_SCHEMA_VERSION)
        .context("jvm manifest schema_version append failed")?;
    root.append_u16(entries.len() as u16)
        .context("jvm manifest count append failed")?;
    if let Some(head) = chain_head {
        root.checked_append_reference(head)
            .context("jvm manifest chain ref append failed")?;
    }
    root.into_cell().context("jvm manifest finalize failed")
}

fn validate_entries(entries: &[JvmMethodManifestEntry]) -> Result<()> {
    if entries.len() > JVM_METHOD_MANIFEST_MAX_ENTRIES {
        return Err(anyhow!(
            "manifest entry count {} exceeds {}",
            entries.len(),
            JVM_METHOD_MANIFEST_MAX_ENTRIES
        ));
    }
    let mut seen_ids: Vec<u32> = entries.iter().map(|e| e.method_id).collect();
    seen_ids.sort_unstable();
    if seen_ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(anyhow!("manifest has duplicate method_id"));
    }
    for (i, e) in entries.iter().enumerate() {
        validate_string("class_name", &e.class_name, i)?;
        validate_string("method_name", &e.method_name, i)?;
        validate_string("method_spec", &e.method_spec, i)?;
    }
    Ok(())
}

fn validate_string(field: &str, s: &str, index: usize) -> Result<()> {
    if s.is_empty() {
        return Err(anyhow!("manifest entry {index}: {field} is empty"));
    }
    if s.as_bytes().contains(&0) {
        return Err(anyhow!("manifest entry {index}: {field} contains NUL"));
    }
    Ok(())
}

fn encode_chain(entries: &[JvmMethodManifestEntry]) -> Result<Cell> {
    let mut next: Option<Cell> = None;
    for entry in entries.iter().rev() {
        let class_name = encode_jvm_storage_value(entry.class_name.as_bytes())
            .context("manifest class_name encode failed")?;
        let method_name = encode_jvm_storage_value(entry.method_name.as_bytes())
            .context("manifest method_name encode failed")?;
        let method_spec = encode_jvm_storage_value(entry.method_spec.as_bytes())
            .context("manifest method_spec encode failed")?;

        let mut node = BuilderData::new();
        node.append_u32(entry.method_id)
            .context("manifest method_id append failed")?;
        match next.take() {
            Some(child) => {
                node.append_bit_one()
                    .context("manifest has_next bit failed")?;
                node.checked_append_reference(child)
                    .context("manifest next ref append failed")?;
            }
            None => {
                node.append_bit_zero()
                    .context("manifest tail bit failed")?;
            }
        }
        node.checked_append_reference(class_name)
            .context("manifest class_name ref append failed")?;
        node.checked_append_reference(method_name)
            .context("manifest method_name ref append failed")?;
        node.checked_append_reference(method_spec)
            .context("manifest method_spec ref append failed")?;
        next = Some(
            node.into_cell().context("manifest node finalize failed")?,
        );
    }
    Ok(next.expect("non-empty entries always produce at least one node"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u32) -> JvmMethodManifestEntry {
        JvmMethodManifestEntry::new(
            id,
            "java/lang/Wallet",
            "init",
            "(Ljava/lang/Bytes32;)V",
        )
    }

    #[test]
    fn empty_manifest_is_header_only() {
        let cell = encode_jvm_method_manifest(&[]).expect("encode");
        assert_eq!(
            cell.references_count(),
            0,
            "empty manifest must have no child refs"
        );
    }

    #[test]
    fn three_entry_manifest_has_one_root_ref() {
        let entries = vec![entry(1), entry(2), entry(3)];
        let cell = encode_jvm_method_manifest(&entries).expect("encode");
        assert_eq!(cell.references_count(), 1);
    }

    #[test]
    fn manifest_encoding_is_deterministic() {
        let entries = vec![entry(0xaaaa_bbbb), entry(0xccc_dddd)];
        let a = encode_jvm_method_manifest(&entries).expect("encode a");
        let b = encode_jvm_method_manifest(&entries).expect("encode b");
        assert_eq!(a.repr_hash(), b.repr_hash());
    }

    #[test]
    fn manifest_rejects_duplicate_method_id() {
        let entries = vec![entry(7), entry(7)];
        let err = encode_jvm_method_manifest(&entries).unwrap_err();
        assert!(format!("{err}").contains("duplicate method_id"));
    }

    #[test]
    fn manifest_rejects_empty_string() {
        let entries = vec![JvmMethodManifestEntry::new(1, "", "x", "()V")];
        let err = encode_jvm_method_manifest(&entries).unwrap_err();
        assert!(format!("{err}").contains("class_name"));
    }
}
