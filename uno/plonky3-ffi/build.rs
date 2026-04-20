//! Build script for uno_plonky3_ffi.
//!
//! Runs cbindgen to (re-)generate `include/uno_plonky3_ffi.h` whenever
//! `src/lib.rs` changes. The generated header is committed to the tree
//! as well (see CI gate in Agent 5's CMake), so downstream C++ consumers
//! never need a Rust toolchain just to read the public FFI surface.
//!
//! If cbindgen fails (e.g. on a minimal developer env without the tool
//! installed), we print a warning and continue — the committed header
//! stays as the source of truth for the FFI surface until the next
//! successful regeneration.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let crate_path = PathBuf::from(&crate_dir);

    // Re-emit only when the surface-defining files change.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");

    // Allow downstream (Agent 5) to disable header regen entirely, e.g. in
    // an offline CI where the developer toolchain lacks cbindgen but the
    // committed header is authoritative.
    if env::var_os("UNO_PLONKY3_SKIP_CBINDGEN").is_some() {
        println!("cargo:warning=UNO_PLONKY3_SKIP_CBINDGEN set; leaving include/uno_plonky3_ffi.h as-is");
        return;
    }

    let config = match cbindgen::Config::from_file(crate_path.join("cbindgen.toml")) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "cargo:warning=uno_plonky3_ffi: failed to read cbindgen.toml: {e}; keeping committed header"
            );
            return;
        }
    };

    let out_header = crate_path.join("include").join("uno_plonky3_ffi.h");

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            // Only overwrite if content differs — keeps mtime stable for
            // Agent 5's CMake dependency tracking.
            bindings.write_to_file(&out_header);
        }
        Err(e) => {
            println!(
                "cargo:warning=uno_plonky3_ffi: cbindgen failed to generate header: {e}; keeping committed header"
            );
        }
    }
}
