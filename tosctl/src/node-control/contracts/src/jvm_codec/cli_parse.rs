/*
 * CLI-friendly parsers for JVM typed args + method-manifest JSON.
 *
 * Lives in the consensus-aware `contracts` crate (not the `commands`
 * crate) so any future tooling that needs the same parsing semantics
 * can call into it directly, and so unit tests run alongside the
 * codec parity tests.
 *
 * The parsing semantics are NOT consensus-stable on their own — they
 * are off-chain conveniences for human input.  But the underlying
 * encoded cells they produce are exactly the consensus-stable shapes
 * locked by `jvm-codec-reference.txt`.
 */
use anyhow::{anyhow, bail, Context, Result};
use chain_block::Cell;

use super::args::JvmTypedArg;
#[cfg(test)]
use super::args::JvmArgType;
use super::manifest::{encode_jvm_method_manifest, JvmMethodManifestEntry};
use crate::jvm_wallet::method_id_of;

/// Parse one `--arg type:value` spec into a `JvmTypedArg`.
///
/// Supported type tags (lowercase; all `value` payloads accept an
/// optional `0x` prefix on hex):
///
///   * `bool:true` / `bool:false`
///   * `int:<i32 decimal>`           — Java int (4 BE bytes)
///   * `long:<i64 decimal>`          — Java long (8 BE bytes)
///   * `uint256:<32-byte hex>`       — 32 BE bytes
///   * `bytes32:<32-byte hex>`       — 32 BE bytes
///   * `bytes4:<4-byte hex>`         — 4 BE bytes
///   * `address:<wc>:<32-byte hex>`  — 36 bytes (4 BE wc + 32 byte
///                                     account_id)
///   * `bytes:<hex-bytes>`           — variable length (any size up to
///                                     `JVM_STORAGE_VALUE_MAX_BYTES`)
///
/// Returns an error with a precise human-readable message on any
/// unrecognized tag, hex parse failure, or length mismatch.
pub fn parse_typed_arg(spec: &str) -> Result<JvmTypedArg> {
    let (tag, rest) = spec.split_once(':').ok_or_else(|| {
        anyhow!(
            "expected `type:value` form (e.g. `uint256:0x42..`); got `{}`",
            spec
        )
    })?;
    match tag {
        "bool" => match rest {
            "true" => Ok(JvmTypedArg::bool_(true)),
            "false" => Ok(JvmTypedArg::bool_(false)),
            other => bail!("bool arg must be `true` or `false`, got `{}`", other),
        },
        "int" => {
            let v: i32 = rest
                .parse()
                .with_context(|| format!("int arg `{}` not a valid i32", rest))?;
            Ok(JvmTypedArg::int32(v))
        }
        "long" => {
            let v: i64 = rest.parse().with_context(|| {
                format!("long arg `{}` not a valid i64", rest)
            })?;
            Ok(JvmTypedArg::int64(v))
        }
        "uint256" => {
            let raw = parse_hex_fixed(rest, 32, "uint256")?;
            Ok(JvmTypedArg::uint256(raw))
        }
        "bytes32" => {
            let raw = parse_hex_fixed(rest, 32, "bytes32")?;
            Ok(JvmTypedArg::bytes32(raw))
        }
        "bytes4" => {
            let raw = parse_hex_fixed(rest, 4, "bytes4")?;
            Ok(JvmTypedArg::bytes4(raw))
        }
        "address" => {
            // `address:<wc>:<hex32>` — split on the first colon only,
            // the second `:` separates wc from account_id.
            let (wc_str, addr_str) = rest.split_once(':').ok_or_else(|| {
                anyhow!(
                    "address arg expects `address:<wc>:<32-byte hex>`; got `{}`",
                    rest
                )
            })?;
            let wc: i32 = wc_str.parse().with_context(|| {
                format!("address workchain `{}` not a valid i32", wc_str)
            })?;
            let raw = parse_hex_fixed(addr_str, 32, "address account_id")?;
            Ok(JvmTypedArg::address(wc, raw))
        }
        "bytes" => {
            let raw = parse_hex_var(rest, "bytes")?;
            Ok(JvmTypedArg::raw_bytes(raw))
        }
        unknown => bail!(
            "unknown arg type `{}` (expected one of: bool, int, long, \
             uint256, bytes32, bytes4, address, bytes)",
            unknown
        ),
    }
}

/// Parse a list of `--arg` specs into a Vec.  Preserves input order
/// — the JVM ABI is positional, so the caller must pass args in the
/// same order the method signature declares them.
pub fn parse_typed_args(specs: &[String]) -> Result<Vec<JvmTypedArg>> {
    specs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            parse_typed_arg(s)
                .with_context(|| format!("arg #{}: `{}`", i, s))
        })
        .collect()
}

/// JSON shape for `--manifest-file`.  Each entry binds an ABI
/// signature (used both for the method_id derivation and for
/// human-readable record-keeping) to the JNI internal class name and
/// the type-spec descriptor the dispatch engine needs to call into
/// the JVM method.
///
/// Example:
/// ```json
/// [
///   {
///     "abi_sig": "init(bytes32)",
///     "class_name": "com/example/Counter",
///     "method_name": "init",
///     "method_spec": "(Ljava/lang/Bytes32;)V"
///   },
///   {
///     "abi_sig": "increment()",
///     "class_name": "com/example/Counter",
///     "method_name": "increment",
///     "method_spec": "()V"
///   }
/// ]
/// ```
#[derive(serde::Deserialize)]
pub struct ManifestEntrySpec {
    pub abi_sig: String,
    pub class_name: String,
    pub method_name: String,
    pub method_spec: String,
}

/// Parse a manifest JSON blob into encoded `JvmMethodManifestEntry`
/// values.  Each entry's `method_id` is derived from `abi_sig` via
/// `method_id_from_signature` (first 4 bytes of `keccak256(abi_sig)`)
/// — the same derivation `java.lang.Wallet` / `java.lang.Deployer`
/// use, and the same one consensus uses to dispatch incoming calls.
pub fn parse_manifest_json(
    json: &str,
) -> Result<Vec<JvmMethodManifestEntry>> {
    let specs: Vec<ManifestEntrySpec> = serde_json::from_str(json)
        .context("manifest JSON parse failed")?;
    if specs.is_empty() {
        bail!(
            "manifest must declare at least one method entry; an empty \
             manifest would produce a contract that cannot be called"
        );
    }
    let mut entries = Vec::with_capacity(specs.len());
    let mut seen_ids = std::collections::HashSet::new();
    for (i, s) in specs.iter().enumerate() {
        let method_id = method_id_of(&s.abi_sig);
        if !seen_ids.insert(method_id) {
            bail!(
                "manifest entry #{}: method_id 0x{:08x} (derived from \
                 `{}`) already used by a prior entry — duplicate \
                 method_ids are rejected by the consensus encoder",
                i,
                method_id,
                s.abi_sig
            );
        }
        entries.push(JvmMethodManifestEntry::new(
            method_id,
            &s.class_name,
            &s.method_name,
            &s.method_spec,
        ));
    }
    Ok(entries)
}

/// Parse a manifest JSON blob into a single encoded manifest cell —
/// convenience for callers that want the final cell directly.
pub fn parse_manifest_cell(json: &str) -> Result<Cell> {
    let entries = parse_manifest_json(json)?;
    encode_jvm_method_manifest(&entries)
        .context("encode manifest cell failed")
}

/// Parse a `wc:hex32` address spec into (workchain, account_id).
/// Workchain is parsed as `i32` so the wc=-1 masterchain is
/// expressible.
pub fn parse_workchain_address(spec: &str) -> Result<(i32, [u8; 32])> {
    let (wc_str, hex_str) = spec.split_once(':').ok_or_else(|| {
        anyhow!(
            "expected `wc:hex32` form (e.g. `3:0xabcd..`); got `{}`",
            spec
        )
    })?;
    let wc: i32 = wc_str
        .parse()
        .with_context(|| format!("workchain `{}` not a valid i32", wc_str))?;
    let raw = parse_hex_fixed(hex_str, 32, "account_id")?;
    Ok((wc, raw))
}

// ─────────────────────── internal helpers ───────────────────────────

fn parse_hex_fixed<const N: usize>(
    raw: &str,
    _expected_bytes: usize,
    field: &str,
) -> Result<[u8; N]> {
    let stripped = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(stripped).with_context(|| {
        format!("{} value `{}` is not valid hex", field, raw)
    })?;
    if bytes.len() != N {
        bail!(
            "{} value `{}` decoded to {} bytes, expected exactly {}",
            field,
            raw,
            bytes.len(),
            N
        );
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_var(raw: &str, field: &str) -> Result<Vec<u8>> {
    let stripped = raw.strip_prefix("0x").unwrap_or(raw);
    hex::decode(stripped).with_context(|| {
        format!("{} value `{}` is not valid hex", field, raw)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typed_arg_bool_int_long() {
        let t = parse_typed_arg("bool:true").unwrap();
        assert_eq!(t.arg_type, JvmArgType::Bool);
        let f = parse_typed_arg("bool:false").unwrap();
        assert_eq!(f.arg_type, JvmArgType::Bool);
        let i = parse_typed_arg("int:-42").unwrap();
        assert_eq!(i.arg_type, JvmArgType::Int32);
        let l = parse_typed_arg("long:1234567890123").unwrap();
        assert_eq!(l.arg_type, JvmArgType::Int64);
    }

    #[test]
    fn parse_typed_arg_hex_types_accept_with_and_without_prefix() {
        let a = parse_typed_arg(
            "bytes32:0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let b = parse_typed_arg(
            "bytes32:0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.arg_type, JvmArgType::Bytes32);
    }

    #[test]
    fn parse_typed_arg_address() {
        let a = parse_typed_arg(
            "address:3:0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        assert_eq!(a.arg_type, JvmArgType::Address);
        assert_eq!(a.bytes.len(), 36);
        // workchain = 3 in BE
        assert_eq!(&a.bytes[..4], &[0, 0, 0, 3]);
        assert_eq!(a.bytes[35], 0x42);
    }

    #[test]
    fn parse_typed_arg_rejects_wrong_length() {
        // bytes32 with 16 bytes:
        let err = parse_typed_arg("bytes32:0x1234").unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("decoded to 2 bytes, expected exactly 32"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn parse_typed_arg_rejects_unknown_tag() {
        let err = parse_typed_arg("uint128:42").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("unknown arg type"), "got: {}", msg);
    }

    #[test]
    fn parse_manifest_json_round_trips() {
        let json = r#"[
            {
                "abi_sig": "init(bytes32)",
                "class_name": "com/example/Counter",
                "method_name": "init",
                "method_spec": "(Ljava/lang/Bytes32;)V"
            },
            {
                "abi_sig": "increment()",
                "class_name": "com/example/Counter",
                "method_name": "increment",
                "method_spec": "()V"
            }
        ]"#;
        let entries = parse_manifest_json(json).unwrap();
        assert_eq!(entries.len(), 2);
        // method_id ordering: derive from abi_sig.
        assert_eq!(entries[0].method_id, method_id_of("init(bytes32)"));
        assert_eq!(entries[1].method_id, method_id_of("increment()"));
    }

    #[test]
    fn parse_manifest_json_rejects_duplicate_method_ids() {
        // Two entries with the same abi_sig → same method_id.
        let json = r#"[
            {"abi_sig":"foo()","class_name":"c","method_name":"foo","method_spec":"()V"},
            {"abi_sig":"foo()","class_name":"c","method_name":"foo","method_spec":"()V"}
        ]"#;
        let err = parse_manifest_json(json).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("duplicate method_ids"), "got: {}", msg);
    }

    #[test]
    fn parse_manifest_json_rejects_empty() {
        let err = parse_manifest_json("[]").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("at least one method"), "got: {}", msg);
    }

    #[test]
    fn parse_workchain_address_basic() {
        let (wc, id) = parse_workchain_address(
            "3:0x0000000000000000000000000000000000000000000000000000000000000abc",
        )
        .unwrap();
        assert_eq!(wc, 3);
        assert_eq!(id[30], 0x0a);
        assert_eq!(id[31], 0xbc);
    }

    #[test]
    fn parse_workchain_address_rejects_bad_form() {
        let err = parse_workchain_address("3-0xdead").unwrap_err();
        assert!(format!("{}", err).contains("wc:hex32"));
    }
}
