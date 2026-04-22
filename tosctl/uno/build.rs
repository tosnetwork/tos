//! Build script for `tosctl-uno`.
//!
//! Sole job (V1-3c-beta): propagate the optional `BOC_PARITY_BRIDGE`
//! environment variable (absolute path to the C++ `boc-parity-bridge`
//! helper binary) into the compiled test binary via `rustc-env`, so
//! `tests/boc_parity.rs` can locate it through
//! `option_env!("BOC_PARITY_BRIDGE")` at compile time.
//!
//! When unset, `option_env!` returns `None` and the parity tests emit a
//! clear SKIP line in their body. This lets `cargo test` pass cleanly in
//! environments where the C++ bridge has not been built.

fn main() {
    println!("cargo:rerun-if-env-changed=BOC_PARITY_BRIDGE");
    if let Ok(path) = std::env::var("BOC_PARITY_BRIDGE") {
        println!("cargo:rustc-env=BOC_PARITY_BRIDGE={}", path);
    }
}
