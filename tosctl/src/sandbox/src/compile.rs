/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! FunC → Cell compilation helper.
//!
//! Compiles FunC smart contract source files to TVM code [`Cell`]s by invoking
//! the `func` compiler and `fift` assembler as external processes.
//!
//! # Example
//! ```ignore
//! use tos_sandbox::compile::compile_func;
//!
//! let code = compile_func(&["contracts/counter.fc"]).unwrap();
//! // `code` is a Cell containing the compiled TVM bytecode
//! ```

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use chain_block::{Cell, read_single_root_boc};

use crate::error::{SandboxError, SandboxResult};

/// Locate the TOS build directory by checking common paths.
fn find_tos_root() -> Option<PathBuf> {
    // 1. Check TOS_ROOT env var
    if let Ok(root) = env::var("TOS_ROOT") {
        let p = PathBuf::from(root);
        if p.join("build/crypto/func").exists() {
            return Some(p);
        }
    }

    // 2. Check ~/tos
    if let Ok(home) = env::var("HOME") {
        let p = PathBuf::from(&home).join("tos");
        if p.join("build/crypto/func").exists() {
            return Some(p);
        }
    }

    // 3. Check relative to current dir (common in workspace)
    for candidate in &[".", "..", "../..", "../../.."] {
        let p = PathBuf::from(candidate);
        if p.join("build/crypto/func").exists() {
            return Some(p);
        }
    }

    None
}

/// Compile one or more FunC source files into a TVM code [`Cell`].
///
/// The function invokes the `func` compiler to produce Fift assembly, then
/// runs `fift` to assemble it into a BOC (Bag of Cells), and finally
/// deserializes the BOC into a [`Cell`].
///
/// # Arguments
/// * `sources` — paths to `.fc` / `.func` source files.  If the contract
///   uses `#include "stdlib.fc"`, either place `stdlib.fc` next to the
///   source or pass it explicitly as the first element:
///   ```ignore
///   compile_func(&["path/to/stdlib.fc", "path/to/my_contract.fc"])
///   ```
///
/// # Environment
/// * `TOS_ROOT` — if set, used to locate `build/crypto/func`, `build/crypto/fift`,
///   and `crypto/fift/lib`.  Falls back to `~/tos` or relative paths.
/// * `FUNC_PATH` — override the path to the `func` binary.
/// * `FIFT_PATH` — override the path to the `fift` binary.
///
/// # Errors
/// Returns [`SandboxError`] if the compiler or assembler fails, or if the
/// resulting BOC cannot be deserialized.
pub fn compile_func(sources: &[impl AsRef<Path>]) -> SandboxResult<Cell> {
    if sources.is_empty() {
        return Err(SandboxError::InvalidMessage(
            "compile_func: no source files provided".into(),
        ));
    }

    let tos_root = find_tos_root();

    // Resolve func binary
    let func_bin = env::var("FUNC_PATH")
        .map(PathBuf::from)
        .ok()
        .or_else(|| tos_root.as_ref().map(|r| r.join("build/crypto/func")))
        .ok_or_else(|| {
            SandboxError::ConfigError(
                "Cannot find func compiler. Set TOS_ROOT or FUNC_PATH.".into(),
            )
        })?;

    // Resolve fift binary
    let fift_bin = env::var("FIFT_PATH")
        .map(PathBuf::from)
        .ok()
        .or_else(|| tos_root.as_ref().map(|r| r.join("build/crypto/fift")))
        .ok_or_else(|| {
            SandboxError::ConfigError(
                "Cannot find fift binary. Set TOS_ROOT or FIFT_PATH.".into(),
            )
        })?;

    // Resolve fift include path
    let fift_includes = tos_root
        .as_ref()
        .map(|r| {
            format!(
                "{}:{}",
                r.join("crypto/fift/lib").display(),
                r.join("crypto/smartcont").display()
            )
        })
        .unwrap_or_default();

    // Create a temp directory for intermediate files
    let tmp = tempfile::tempdir()
        .map_err(|e| SandboxError::Serialization(format!("tmpdir: {e}")))?;
    let fif_path = tmp.path().join("output.fif");
    let boc_path = tmp.path().join("output.boc");

    // Step 1: func → Fift assembly
    let mut func_cmd = Command::new(&func_bin);
    func_cmd.args(["-SPA", "-o"]);
    func_cmd.arg(&fif_path);
    for src in sources {
        func_cmd.arg(src.as_ref());
    }
    let func_output = func_cmd.output().map_err(|e| {
        SandboxError::ConfigError(format!("Failed to run func at {}: {e}", func_bin.display()))
    })?;
    if !func_output.status.success() {
        let stderr = String::from_utf8_lossy(&func_output.stderr);
        let stdout = String::from_utf8_lossy(&func_output.stdout);
        return Err(SandboxError::Serialization(format!(
            "func compilation failed:\n{stderr}\n{stdout}"
        )));
    }

    // Step 2: Fift assembly → BOC
    let fift_script = format!(
        "\"Asm.fif\" include\n\"{}\" include\n2 boc+>B \"{}\" B>file\n",
        fif_path.display(),
        boc_path.display()
    );
    let fift_script_path = tmp.path().join("assemble.fif");
    std::fs::write(&fift_script_path, &fift_script)
        .map_err(|e| SandboxError::Serialization(format!("write fift script: {e}")))?;

    let fift_output = Command::new(&fift_bin)
        .args(["-I", &fift_includes, "-s"])
        .arg(&fift_script_path)
        .output()
        .map_err(|e| {
            SandboxError::ConfigError(format!(
                "Failed to run fift at {}: {e}",
                fift_bin.display()
            ))
        })?;
    if !fift_output.status.success() {
        let stderr = String::from_utf8_lossy(&fift_output.stderr);
        return Err(SandboxError::Serialization(format!(
            "fift assembly failed:\n{stderr}"
        )));
    }

    // Step 3: Read the BOC and deserialize
    if !boc_path.exists() {
        return Err(SandboxError::Serialization(
            "fift did not produce output BOC".into(),
        ));
    }
    let boc_bytes = std::fs::read(&boc_path)
        .map_err(|e| SandboxError::Serialization(format!("read BOC: {e}")))?;
    let cell = read_single_root_boc(boc_bytes)
        .map_err(|e| SandboxError::Serialization(format!("parse BOC: {e}")))?;

    Ok(cell)
}

/// Compile FunC source files with the standard library automatically included.
///
/// This is a convenience wrapper around [`compile_func`] that prepends
/// `stdlib.fc` from the TOS source tree.
///
/// # Example
/// ```ignore
/// let code = compile_func_with_stdlib(&["contracts/counter.fc"]).unwrap();
/// ```
pub fn compile_func_with_stdlib(sources: &[impl AsRef<Path>]) -> SandboxResult<Cell> {
    let tos_root = find_tos_root().ok_or_else(|| {
        SandboxError::ConfigError("Cannot find TOS root for stdlib.fc".into())
    })?;

    let stdlib = tos_root.join("crypto/smartcont/stdlib.fc");
    if !stdlib.exists() {
        return Err(SandboxError::ConfigError(format!(
            "stdlib.fc not found at {}",
            stdlib.display()
        )));
    }

    let mut all_sources: Vec<PathBuf> = vec![stdlib];
    for s in sources {
        all_sources.push(s.as_ref().to_path_buf());
    }
    compile_func(&all_sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_simple_contract() {
        // Write a minimal contract to a temp file
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("simple.fc");
        std::fs::write(
            &src,
            r#"
            () recv_internal(int a, cell b, slice c) impure { }
            int answer() method_id { return 42; }
            "#,
        )
        .unwrap();

        let cell = compile_func(&[&src]).expect("compilation should succeed");
        // The cell should be non-empty
        assert!(cell.bit_length() > 0 || cell.references_count() > 0);
    }

    #[test]
    fn test_compile_with_stdlib() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("with_stdlib.fc");
        std::fs::write(
            &src,
            r#"
            () recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
                if (in_msg_body.slice_empty?()) { return (); }
                int op = in_msg_body~load_uint(32);
            }
            int get_counter() method_id { return 123; }
            "#,
        )
        .unwrap();

        let cell = compile_func_with_stdlib(&[&src]).expect("compilation with stdlib should succeed");
        assert!(cell.bit_length() > 0 || cell.references_count() > 0);
    }
}
